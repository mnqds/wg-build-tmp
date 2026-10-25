//
//  WatermarkGuard.m
//  通用 iOS「卡密验证 + 全局水印」dylib
//
//  兼容：iOS 14 ~ 18 / arm64 / UIKit · SwiftUI · SceneDelegate · AppDelegate 全架构
//  原则：核心自洽、增强可关、失败静默、绝不主动让宿主崩溃
//

#import "WatermarkGuard.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
#import <sys/proc.h>
#import <sys/ptrace.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <stdlib.h>
#import <string.h>
#import <CFNetwork/CFNetwork.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

/* 兜底：个别精简 SDK 可能缺这两个宏 */
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

/* 仅用于 @synchronized 的锚点类 */
@interface WatermarkGuardAnchor : NSObject
@end

/* ============================================================================
 * 一、功能开关（改这里即可，无需动下方逻辑）
 * ==========================================================================*/
#define WG_ENABLE_CORE                 1  // 总开关：0 = 整个 dylib 什么都不做
#define WG_ENABLE_WATERMARK            1  // 核心：全局水印 UI
#define WG_ENABLE_VERIFY               1  // 核心：独立卡密验证
#define WG_ENABLE_DEBUGGER_CHECK       1  // 增强：反调试（默认开，误杀极低）
#define WG_ENABLE_FRIDA_CHECK          1  // 增强：Frida / Cycript 检测（默认开）
#define WG_ENABLE_SELF_INTEGRITY       1  // 增强：自身完整性校验（默认开）
#define WG_ENABLE_JAILBREAK_CHECK      0  // 增强：越狱检测（误杀中等，默认关）
#define WG_ENABLE_MULTIOPEN_CHECK      0  // 增强：多开/分身检测（误杀中等，默认关）
#define WG_ENABLE_PROXY_CHECK          0  // 增强：系统代理检测（误杀高，默认关）
#define WG_ENABLE_SIMULATOR_CHECK      0  // 增强：模拟器检测（误判高，默认关）
#define WG_ENABLE_SSL_PINNING          0  // 增强：验证接口证书绑定（默认关）
#define WG_ENABLE_HTTP_HEADER_HOOK     0  // 增强：给原生请求追加 Header（默认关）
#define WG_ENABLE_FORCE_EXIT_L3        1  // 三级异常是否 exit(0)：1 开启（按需求）

/* ============================================================================
 * 二、常量配置（部署前必改）
 * ==========================================================================*/
static NSString *const kWGVerifyURL        = @"https://example.com/api/verify"; // ← 改成你自己的验证接口
static NSString *const kWGCardDefaultsKey  = @"licenseCode";                    // ← 卡密在 NSUserDefaults 的字段名
static NSString *const kWGAppID            = @"app_001";                        // ← 多软件隔离用
static NSString *const kWGPlatform         = @"ios";
static NSString *const kWGDefaultWaterText = @"未授权 · 请激活";                 // 接口返回空 water_text 时的兜底文案
static NSString *const kWGRiskLevel1Text   = @"⚠ 运行环境异常";                  // 一级异常追加到水印的文字
static NSString *const kWGPinnedCertSHA256 = @"";                               // 开启 Pinning 时填证书 SHA256(hex)
static NSString *const kWGHTTPHookKeyword  = @"/api/";                          // 仅拦截 URL 含此关键字的 POST 请求

static const NSTimeInterval kWGFirstDelay       = 60.0;   // 首次校验延迟（秒）
static const NSTimeInterval kWGVerifyInterval   = 120.0;  // 前台校验间隔（秒）
static const NSTimeInterval kWGSecurityInterval = 60.0;   // 安全复检间隔（秒）
static const NSTimeInterval kWGRequestTimeout   = 10.0;   // 验证请求超时（秒）
static const NSInteger      kWGAnomalyAlertLevel = 2;     // 连续 N 次弹提示框
static const NSInteger      kWGAnomalyExitLevel  = 3;     // 连续 N 次强制退出

/* ============================================================================
 * 三、内部状态
 * ==========================================================================*/
static UIWindow *gOverlayWindow = nil;
static UILabel  *gWaterLabel    = nil;
static NSString *gWaterText     = nil;   // 接口下发的文案
static NSString *gRiskText      = nil;   // 安全模块追加的风险文案
static BOOL      gWaterHidden   = YES;   // YES = 无水印
static BOOL      gStarted       = NO;
static int       gSceneRetry    = 0;    // 等待 UIWindowScene 的重试计数

static NSMutableDictionary<NSString *, NSNumber *> *gAnomalyCounts = nil;
static NSMutableSet<NSString *> *gAlertedItems = nil;
static uint32_t  gSelfFingerprint = 0;

static dispatch_queue_t gVerifyQueue = NULL;
static dispatch_queue_t gSecurityQueue = NULL;
static dispatch_source_t gVerifyTimer = NULL;
static dispatch_source_t gSecurityTimer = NULL;

/* 前向声明 */
static void WGEnsureOverlay(void);
static void WGApplyWatermark(void);
static void WGSetWatermark(BOOL hidden, NSString *text);
static void WGSetRiskText(NSString *text);
static void WGShowAnomalyAlert(NSString *message);
static void WGPerformVerify(void);
static BOOL WGIsAppActive(void);

/* ============================================================================
 * 四、通用小工具
 * ==========================================================================*/
static void WGLog(NSString *fmt, ...) {
#ifdef WG_DEBUG_LOG
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[WatermarkGuard] %@", s);
#endif
}

static NSString *WGURLEncode(NSString *s) {
    if (s.length == 0) return @"";
    NSCharacterSet *allowed = [NSCharacterSet alphanumericCharacterSet];
    NSString *r = [s stringByAddingPercentEncodingWithAllowedCharacters:allowed];
    return r ?: @"";
}

/// 宽松布尔解析：兼容 true/false、"true"/"1"/"yes"、1/0
static BOOL WGBoolValue(id v) {
    if (!v || v == [NSNull null]) return NO;
    if ([v isKindOfClass:[NSNumber class]]) return [v boolValue];
    if ([v isKindOfClass:[NSString class]]) {
        NSString *s = [(NSString *)v lowercaseString];
        return ([s isEqualToString:@"true"] || [s isEqualToString:@"1"] || [s isEqualToString:@"yes"]);
    }
    return NO;
}

static volatile int32_t gAppStateCache = 1;   // 1 = 前台，0 = 其它（后台/失活）

static BOOL WGIsAppActive(void) {
    if ([NSThread isMainThread]) {
        @try {
            return [UIApplication sharedApplication].applicationState == UIApplicationStateActive;
        } @catch (...) {
            return YES;
        }
    }
    // 子线程：异步回主线程取值并等 0.5 秒。
    // 不用 dispatch_sync —— 宿主主线程若被长时间阻塞会连带卡死检测队列；超时则退回上次缓存值。
    __block BOOL active = YES;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            active = [UIApplication sharedApplication].applicationState == UIApplicationStateActive;
        } @catch (...) {}
        gAppStateCache = active ? 1 : 0;
        dispatch_semaphore_signal(sem);
    });
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC))) != 0) {
        return gAppStateCache != 0;
    }
    return active;
}

static UIWindowScene *WGActiveWindowScene(void) {
    @try {
        UIWindowScene *fallback = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)s;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
            if (!fallback) fallback = ws;
        }
        return fallback;
    } @catch (...) {
        return nil;
    }
}

/* ============================================================================
 * 五、水印 UI（独立 Window，不侵入宿主视图）
 * ==========================================================================*/
@interface WGOverlayController : UIViewController
@end

@implementation WGOverlayController
- (void)loadView {
    UIView *v = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    v.backgroundColor = [UIColor clearColor];
    v.userInteractionEnabled = NO;
    self.view = v;
}
- (BOOL)shouldAutorotate { return YES; }
- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskAll; }
@end

static void WGEnsureOverlay(void) {
    @try {
        if (![NSThread isMainThread]) {
            dispatch_async(dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
            return;
        }
        // 注意：即使水印功能关闭也要允许创建窗口——二级异常的全局提示框需要它做容器。
        // 水印文案的显隐由 WGApplyWatermark 里的 WG_ENABLE_WATERMARK 单独控制，窗口平时保持 hidden。

        if (gOverlayWindow) {
            // 多窗口/多场景切换时重新挂载，避免水印挂在已失活的场景上
            UIWindowScene *cur = gOverlayWindow.windowScene;
            if (!cur) {
                UIWindowScene *s2 = WGActiveWindowScene();
                if (s2) gOverlayWindow.windowScene = s2;
                cur = gOverlayWindow.windowScene;
            }
            // 注意：无 scene（传统 AppDelegate 架构）时不能取 coordinateSpace.bounds，否则 frame 归零
            gOverlayWindow.frame = cur ? cur.coordinateSpace.bounds : [UIScreen mainScreen].bounds;
            return;
        }

        UIWindowScene *ws = WGActiveWindowScene();
        if (!ws) {
            // 场景还没就绪（SwiftUI / SceneDelegate 启动瞬间）：1 秒后重试。
            // 传统 AppDelegate 架构（Info.plist 无 UIApplicationSceneManifest）本就无 scene，
            // 重试 3 次后回落为「无 scene 的 UIWindow」，保证老架构 App 也能显示水印。
            if (gSceneRetry < 3) {
                gSceneRetry++;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
                return;
            }
            WGLog(@"no window scene, fallback to legacy UIWindow");
        }

        UIWindow *w = ws ? [[UIWindow alloc] initWithWindowScene:ws]
                         : [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        w.frame = ws ? ws.coordinateSpace.bounds : [UIScreen mainScreen].bounds;
        w.windowLevel = UIWindowLevelAlert + 1;     // 高于宿主所有页面
        w.backgroundColor = [UIColor clearColor];
        w.userInteractionEnabled = NO;              // 默认不拦截触摸
        w.hidden = YES;

        WGOverlayController *vc = [[WGOverlayController alloc] init];
        w.rootViewController = vc;

        UILabel *l = [[UILabel alloc] init];
        l.translatesAutoresizingMaskIntoConstraints = NO;
        l.numberOfLines = 0;
        l.textAlignment = NSTextAlignmentCenter;
        l.font = [UIFont italicSystemFontOfSize:12.0];                       // 12 号斜体
        l.textColor = [UIColor colorWithWhite:0.55 alpha:0.78];              // 半透明浅灰
        l.backgroundColor = [UIColor clearColor];
        l.userInteractionEnabled = NO;
        l.layer.shadowColor = [UIColor colorWithWhite:1.0 alpha:0.55].CGColor;
        l.layer.shadowOffset = CGSizeZero;
        l.layer.shadowRadius = 1.0;
        l.layer.shadowOpacity = 1.0;
        [w addSubview:l];

        // 底部居中；Auto Layout 天然适配横竖屏与安全区
        [NSLayoutConstraint activateConstraints:@[
            [l.centerXAnchor constraintEqualToAnchor:w.centerXAnchor],
            [l.bottomAnchor constraintEqualToAnchor:w.safeAreaLayoutGuide.bottomAnchor constant:-6.0],
            [l.leadingAnchor constraintGreaterThanOrEqualToAnchor:w.leadingAnchor constant:12.0],
            [l.trailingAnchor constraintLessThanOrEqualToAnchor:w.trailingAnchor constant:-12.0],
        ]];

        gOverlayWindow = w;
        gWaterLabel = l;
        WGLog(@"overlay window created");
    } @catch (...) {
        WGLog(@"ensure overlay failed");
    }
}

static void WGApplyWatermark(void) {
    @try {
        if (![NSThread isMainThread]) {
            dispatch_async(dispatch_get_main_queue(), ^{ WGApplyWatermark(); });
            return;
        }
        if (!WG_ENABLE_WATERMARK) return;
        WGEnsureOverlay();
        if (!gOverlayWindow || !gWaterLabel) return;

        NSMutableString *text = [NSMutableString string];
        // 有风险提示时即使当前「无水印」也要显示（一级异常的处置就是追加文字）
        if (!gWaterHidden || gRiskText.length) {
            [text appendString:(gWaterText.length ? gWaterText : kWGDefaultWaterText)];
            if (gRiskText.length) {
                if (text.length) [text appendString:@"\n"];
                [text appendString:gRiskText];
            }
        }
        gWaterLabel.text = text;
        gOverlayWindow.hidden = (text.length == 0);
        if (text.length == 0) {
            gOverlayWindow.userInteractionEnabled = NO;
            gOverlayWindow.rootViewController.view.userInteractionEnabled = NO;
        }
    } @catch (...) {
        WGLog(@"apply watermark failed");
    }
}

static void WGSetWatermark(BOOL hidden, NSString *text) {
    @try {
        NSString *copy = [text isKindOfClass:[NSString class]] ? [text copy] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                gWaterHidden = hidden;
                if (copy.length) gWaterText = copy;
                WGApplyWatermark();
            } @catch (...) {}
        });
    } @catch (...) {}
}

static void WGSetRiskText(NSString *text) {
    @try {
        NSString *copy = [text copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                gRiskText = copy;
                WGApplyWatermark();
            } @catch (...) {}
        });
    } @catch (...) {}
}

/* ============================================================================
 * 六、卡密验证（独立于宿主业务）
 * ==========================================================================*/
#if WG_ENABLE_SSL_PINNING
@interface WGPinningDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation WGPinningDelegate
- (void)URLSession:(NSURLSession *)session
        didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    @try {
        if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]
            || kWGPinnedCertSHA256.length == 0) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        if (trust == NULL) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, 0);
        if (cert == NULL) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        NSData *data = (__bridge NSData *)SecCertificateCopyData(cert);
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSMutableString *hex = [NSMutableString string];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
        if ([[hex lowercaseString] isEqualToString:[kWGPinnedCertSHA256 lowercaseString]]) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        }
    } @catch (...) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
@end
#endif

static NSURLSession *WGMakeVerifySession(void) {
    @try {
#if WG_ENABLE_SSL_PINNING
        static NSURLSession *session = nil;
        if (!session) {
            NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
            cfg.timeoutIntervalForRequest = kWGRequestTimeout;
            session = [NSURLSession sessionWithConfiguration:cfg delegate:[WGPinningDelegate new] delegateQueue:nil];
        }
        return session;
#else
        return [NSURLSession sharedSession];
#endif
    } @catch (...) {
        return [NSURLSession sharedSession];
    }
}

static void WGPerformVerify(void) {
    @autoreleasepool {
        @try {
            if (!WG_ENABLE_VERIFY) return;

            // 1) 读取卡密：读不到直接跳过本次请求（不改变当前水印状态）
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            id raw = [ud objectForKey:kWGCardDefaultsKey];
            NSString *code = nil;
            if ([raw isKindOfClass:[NSString class]]) code = (NSString *)raw;
            else if ([raw isKindOfClass:[NSNumber class]]) code = [(NSNumber *)raw stringValue];
            code = [code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (code.length == 0) {
                WGLog(@"no card code, skip");
                return;
            }

            // 2) 设备号
            NSString *deviceId = @"";
            @try {
                deviceId = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
            } @catch (...) {
                deviceId = @"";
            }

            // 3) 组装表单（x-www-form-urlencoded，服务端更好兼容）
            NSString *body = [NSString stringWithFormat:@"code=%@&device_id=%@&app_id=%@&platform=%@",
                              WGURLEncode(code), WGURLEncode(deviceId),
                              WGURLEncode(kWGAppID), WGURLEncode(kWGPlatform)];

            NSURL *url = [NSURL URLWithString:kWGVerifyURL];
            if (!url) { WGSetWatermark(YES, nil); return; }

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
            req.HTTPMethod = @"POST";
            req.timeoutInterval = kWGRequestTimeout;
            [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
            req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

            // 4) 请求 + 解析（任何异常一律静默降级：隐藏水印）
            NSURLSessionDataTask *task =
            [WGMakeVerifySession() dataTaskWithRequest:req
                                    completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
                @try {
                    if (err || data.length == 0) { WGSetWatermark(YES, nil); return; }
                    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
                    if (![obj isKindOfClass:[NSDictionary class]]) { WGSetWatermark(YES, nil); return; }
                    NSDictionary *d = (NSDictionary *)obj;
                    BOOL pass = WGBoolValue(d[@"pass"]);
                    id t = d[@"water_text"];
                    NSString *text = [t isKindOfClass:[NSString class]] ? t : nil;
                    WGSetWatermark(pass ? YES : NO, text);
                    WGLog(@"verify pass=%d", (int)pass);
                } @catch (...) {
                    WGSetWatermark(YES, nil);
                }
            }];
            [task resume];
        } @catch (...) {
            WGSetWatermark(YES, nil);   // 超时 / 报错 / 格式异常 → 隐藏水印
        }
    }
}

static void WGStartVerifyTimer(void) {
    @try {
        if (!WG_ENABLE_VERIFY || gVerifyTimer) return;
        gVerifyQueue = dispatch_queue_create("cn.watermarkguard.verify", DISPATCH_QUEUE_SERIAL);
        gVerifyTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gVerifyQueue);
        // 首次 1 分钟后；之后每 120 秒；leeway 2 秒（省电且不影响判断）
        dispatch_source_set_timer(gVerifyTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWGFirstDelay * NSEC_PER_SEC)),
                                  (uint64_t)(kWGVerifyInterval * NSEC_PER_SEC),
                                  (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(gVerifyTimer, ^{
            @try {
                // 后台自动暂停：不触发校验；回前台后的下一次 tick 自动恢复
                if (!WGIsAppActive()) return;
                WGPerformVerify();
                dispatch_async(dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
            } @catch (...) {}
        });
        dispatch_resume(gVerifyTimer);
    } @catch (...) {}
}

/* ============================================================================
 * 七、分级安全防护（全部子线程、全部可关）
 * ==========================================================================*/
static void WGShowAnomalyAlert(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            WGEnsureOverlay();
            UIViewController *host = gOverlayWindow.rootViewController;
            if (!host || host.presentedViewController) return;

            // 弹框前临时放开交互并确保窗口可见，关闭后恢复（不影响宿主触摸）
            gOverlayWindow.hidden = NO;
            gOverlayWindow.userInteractionEnabled = YES;
            host.view.userInteractionEnabled = YES;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"环境异常"
                                                                      message:message
                                                               preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                   style:UIAlertActionStyleDefault
                                                 handler:^(UIAlertAction *a) {
                @try {
                    gOverlayWindow.userInteractionEnabled = NO;
                    host.view.userInteractionEnabled = NO;
                    if (!WG_ENABLE_WATERMARK) {
                        // 水印关闭时 WGApplyWatermark 不会重算显隐，这里手动藏回窗口
                        gOverlayWindow.hidden = YES;
                    }
                    WGApplyWatermark();     // 重算水印显隐，避免窗口一直停留在可见状态
                } @catch (...) {}
            }]];
            [host presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

static void WGReportAnomaly(NSString *name, NSString *desc) {
    @try {
        NSInteger count = 0;
        @synchronized (gAnomalyCounts) {
            if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
            count = [gAnomalyCounts[name] integerValue] + 1;
            gAnomalyCounts[name] = @(count);
        }
        WGLog(@"anomaly %@ x%ld", name, (long)count);

        if (count == 1) {
            // 一级：水印追加风险提示，不弹窗、不闪退
            WGSetRiskText(kWGRiskLevel1Text);
        } else if (count == kWGAnomalyAlertLevel) {
            // 二级：弹一次全局提示
            @synchronized (gAlertedItems) {
                if (!gAlertedItems) gAlertedItems = [NSMutableSet set];
                if (![gAlertedItems containsObject:name]) {
                    [gAlertedItems addObject:name];
                    WGShowAnomalyAlert([NSString stringWithFormat:@"检测到%@，请使用正版环境。", desc]);
                }
            }
        } else if (count >= kWGAnomalyExitLevel && WG_ENABLE_FORCE_EXIT_L3) {
            // 三级：强制退出（可按需把 WG_ENABLE_FORCE_EXIT_L3 置 0 关闭）
            exit(0);
        }
    } @catch (...) {}
}

/// 按「连续」语义更新异常：检出异常 → 计数+1（走分级处置）；恢复正常 → 清零。
/// 当所有检测项都不再异常时，撤掉一级风险水印文字。
static void WGUpdateAnomaly(NSString *name, NSString *desc, BOOL detected) {
    @try {
        if (detected) {
            WGReportAnomaly(name, desc);
            return;
        }
        BOOL hadPositive = NO;
        BOOL anyLeft = NO;
        @synchronized (gAnomalyCounts) {
            if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
            hadPositive = [gAnomalyCounts[name] integerValue] > 0;
            if (hadPositive) gAnomalyCounts[name] = @0;
            for (NSNumber *v in gAnomalyCounts.allValues) {
                if ([v integerValue] > 0) { anyLeft = YES; break; }
            }
        }
        if (hadPositive && !anyLeft) WGSetRiskText(nil);
    } @catch (...) {}
}

#pragma mark - 7.1 反调试

static BOOL WGIsBeingDebugged(void) {
    @try {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
        struct kinfo_proc info;
        memset(&info, 0, sizeof(info));
        size_t size = sizeof(info);
        if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
            return (info.kp_proc.p_flag & P_TRACED) != 0;
        }
    } @catch (...) {}
    return NO;
}

#pragma mark - 7.2 注入框架检测

static BOOL WGHasInjectedFramework(void) {
    @try {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            NSString *s = [NSString stringWithUTF8String:name].lowercaseString;
            if (!s) continue;
            if ([s containsString:@"frida"] ||
                [s containsString:@"cycript"] ||
                [s containsString:@"cynject"] ||
                [s containsString:@"libsubstrate"] ||
                [s containsString:@"substitute"]) {
                return YES;
            }
        }
    } @catch (...) {}
    return NO;
}

#pragma mark - 7.3 自身完整性（运行期函数指纹）

static uint32_t WGFingerprint(void) {
    @try {
        const uint8_t *p = (const uint8_t *)(void *)&WGPerformVerify;
        if (!p) return 0;
        uint32_t h = 2166136261u;
        for (int i = 0; i < 64; i++) { h ^= p[i]; h *= 16777619u; }
        return h;
    } @catch (...) {
        return 0;
    }
}

static BOOL WGIsSelfModified(void) {
    @try {
        if (gSelfFingerprint == 0) return NO;
        return WGFingerprint() != gSelfFingerprint;
    } @catch (...) {
        return NO;
    }
}

#pragma mark - 7.4 越狱 / 多开 / 代理 / 模拟器

static BOOL WGIsJailbroken(void) {
    @try {
        NSArray *paths = @[@"/Applications/Cydia.app",
                           @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                           @"/bin/bash",
                           @"/usr/sbin/sshd",
                           @"/etc/apt",
                           @"/private/var/lib/apt",
                           @"/var/jb"];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *p in paths) {
            if ([fm fileExistsAtPath:p]) return YES;
        }
    } @catch (...) {}
    return NO;
}

static BOOL WGIsMultiOpen(void) {
    @try {
        NSString *path = [[NSBundle mainBundle] bundlePath];
        if ([path containsString:@"/Documents/"]) return YES;
        if ([path containsString:@"/var/mobile/"] && ![path containsString:@"/var/containers/Bundle/Application/"]) return YES;
        const char *env = getenv("DYLD_INSERT_LIBRARIES");
        if (env && strlen(env) > 0 && strstr(env, "WatermarkGuard") == NULL) return YES;
    } @catch (...) {}
    return NO;
}

static BOOL WGHasSystemProxy(void) {
    @try {
        CFDictionaryRef dict = CFNetworkCopySystemProxySettings();
        if (!dict) return NO;
        BOOL on = NO;
        int v = 0;
        // 取到的值不一定是 CFNumber，必须先验类型，否则 CFNumberGetValue 直接崩
        CFTypeRef n = CFDictionaryGetValue(dict, kCFNetworkProxiesHTTPEnable);
        if (n && CFGetTypeID(n) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)n, kCFNumberIntType, &v) && v) on = YES;
        v = 0;
        n = CFDictionaryGetValue(dict, kCFNetworkProxiesHTTPSEnable);
        if (n && CFGetTypeID(n) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)n, kCFNumberIntType, &v) && v) on = YES;
        CFRelease(dict);
        return on;
    } @catch (...) {
        return NO;
    }
}

static BOOL WGIsSimulator(void) {
#if TARGET_OS_SIMULATOR
    return YES;
#else
    return getenv("SIMULATOR_DEVICE_NAME") != NULL;
#endif
}

static void WGRunSecurityChecks(void) {
    @autoreleasepool {
        @try {
#if WG_ENABLE_DEBUGGER_CHECK
            WGUpdateAnomaly(@"debugger", @"调试器", WGIsBeingDebugged());
#endif
#if WG_ENABLE_FRIDA_CHECK
            WGUpdateAnomaly(@"inject", @"注入框架", WGHasInjectedFramework());
#endif
#if WG_ENABLE_SELF_INTEGRITY
            WGUpdateAnomaly(@"selfcheck", @"自身被篡改", WGIsSelfModified());
#endif
#if WG_ENABLE_JAILBREAK_CHECK
            WGUpdateAnomaly(@"jailbreak", @"越狱环境", WGIsJailbroken());
#endif
#if WG_ENABLE_MULTIOPEN_CHECK
            WGUpdateAnomaly(@"multiopen", @"多开环境", WGIsMultiOpen());
#endif
#if WG_ENABLE_PROXY_CHECK
            WGUpdateAnomaly(@"proxy", @"网络代理", WGHasSystemProxy());
#endif
#if WG_ENABLE_SIMULATOR_CHECK
            WGUpdateAnomaly(@"simulator", @"模拟器", WGIsSimulator());
#endif
        } @catch (...) {}
    }
}

static void WGStartSecurityTimer(void) {
    @try {
        if ((!WG_ENABLE_DEBUGGER_CHECK && !WG_ENABLE_FRIDA_CHECK && !WG_ENABLE_SELF_INTEGRITY &&
             !WG_ENABLE_JAILBREAK_CHECK && !WG_ENABLE_MULTIOPEN_CHECK && !WG_ENABLE_PROXY_CHECK &&
             !WG_ENABLE_SIMULATOR_CHECK) || gSecurityTimer) {
            return;
        }
        gSecurityQueue = dispatch_queue_create("cn.watermarkguard.security", DISPATCH_QUEUE_SERIAL);
        gSecurityTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gSecurityQueue);
        dispatch_source_set_timer(gSecurityTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWGSecurityInterval * NSEC_PER_SEC)),
                                  (uint64_t)(kWGSecurityInterval * NSEC_PER_SEC),
                                  (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(gSecurityTimer, ^{
            @try {
                if (!WGIsAppActive()) return;   // 后台不检测，省电
                WGRunSecurityChecks();
            } @catch (...) {}
        });
        dispatch_resume(gSecurityTimer);
    } @catch (...) {}
}

/* ============================================================================
 * 八、可选：原生请求追加 Header（默认关闭）
 *   只加 Header，绝不改 Body；任何异常都退回原始请求
 * ==========================================================================*/
#if WG_ENABLE_HTTP_HEADER_HOOK

typedef NSURLSessionDataTask *(*WGDTHandlerIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDataTask *(*WGDTDelegateIMP)(id, SEL, NSURLRequest *, id);

static WGDTHandlerIMP  gOrigDTHandler  = NULL;
static WGDTDelegateIMP gOrigDTDelegate = NULL;

static NSURLRequest *WGAppendHeaders(NSURLRequest *req) {
    @try {
        if (![req isKindOfClass:[NSURLRequest class]]) return req;
        if (![[req.HTTPMethod uppercaseString] isEqualToString:@"POST"]) return req;
        NSString *url = req.URL.absoluteString;
        if (kWGHTTPHookKeyword.length && ![url containsString:kWGHTTPHookKeyword]) return req;

        NSMutableURLRequest *m = [req mutableCopy];
        NSString *deviceId = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
        if (![m valueForHTTPHeaderField:@"device_id"]) [m setValue:deviceId forHTTPHeaderField:@"device_id"];
        if (![m valueForHTTPHeaderField:@"app_id"])    [m setValue:kWGAppID forHTTPHeaderField:@"app_id"];
        return m;
    } @catch (...) {
        return req;
    }
}

static NSURLSessionDataTask *WGDTWithHandler(id self, SEL _cmd, NSURLRequest *req,
                                             void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        req = WGAppendHeaders(req);
    } @catch (...) {}
    return gOrigDTHandler ? gOrigDTHandler(self, _cmd, req, handler) : nil;
}

static NSURLSessionDataTask *WGDTWithDelegate(id self, SEL _cmd, NSURLRequest *req, id delegate) {
    @try {
        req = WGAppendHeaders(req);
    } @catch (...) {}
    return gOrigDTDelegate ? gOrigDTDelegate(self, _cmd, req, delegate) : nil;
}

static void WGInstallURLSessionHook(void) {
    @try {
        Class cls = NSClassFromString(@"NSURLSession");
        if (!cls) return;

        SEL sel1 = @selector(dataTaskWithRequest:completionHandler:);
        Method m1 = class_getInstanceMethod(cls, sel1);
        if (m1 && !gOrigDTHandler) {
            gOrigDTHandler = (WGDTHandlerIMP)method_getImplementation(m1);
            method_setImplementation(m1, (IMP)WGDTWithHandler);
        }

        SEL sel2 = @selector(dataTaskWithRequest:delegate:);
        Method m2 = class_getInstanceMethod(cls, sel2);
        if (m2 && !gOrigDTDelegate) {
            gOrigDTDelegate = (WGDTDelegateIMP)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)WGDTWithDelegate);
        }
        WGLog(@"urlsession hook installed");
    } @catch (...) {
        WGLog(@"urlsession hook failed, skipped");
    }
}
#endif /* WG_ENABLE_HTTP_HEADER_HOOK */

/* ============================================================================
 * 九、启动入口
 * ==========================================================================*/
void WGStart(void) {
    @try {
        if (!WG_ENABLE_CORE) return;
        @synchronized ([WatermarkGuardAnchor class]) {
            if (gStarted) return;
            gStarted = YES;
        }

#if WG_ENABLE_DEBUGGER_CHECK
        // 主动拒绝调试器附加（失败也无副作用）
        @try { ptrace(PT_DENY_ATTACH, 0, NULL, 0); } @catch (...) {}
#endif

        gSelfFingerprint = WGFingerprint();
        if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
        if (!gAlertedItems) gAlertedItems = [NSMutableSet set];

#if WG_ENABLE_HTTP_HEADER_HOOK
        WGInstallURLSessionHook();
#endif

        // 核心：验证定时器（首次 1 分钟后）
#if WG_ENABLE_VERIFY
        WGStartVerifyTimer();
#else
        // 只开水印、关掉验证时，没有接口判定就直接常显兜底文案（否则水印永远不出来）
        if (WG_ENABLE_WATERMARK) WGSetWatermark(NO, nil);
#endif
        // 增强：安全复检（每 60 秒）
        WGStartSecurityTimer();

        // UI：推迟到 App 启动完成、场景就绪后再创建
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
    } @catch (...) {
        WGLog(@"start failed");
    }
}

/// 仅用于 @synchronized 的锚点类
@implementation WatermarkGuardAnchor
@end

__attribute__((constructor))
static void WatermarkGuardConstructor(void) {
    @autoreleasepool {
        @try { WGStart(); } @catch (...) {}
    }
}
