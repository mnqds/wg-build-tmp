//
//  WatermarkGuard.h
//  通用「卡密验证 + 全局水印」dylib（用于注入已砸壳 IPA）
//
//  设计原则：
//   1. 核心功能（验证 / 水印 / 设备号）完全自洽，不 Hook 宿主业务、不改宿主流程；
//   2. 所有增强功能独立开关，失败自动静默降级，绝不抛异常给宿主；
//   3. UI 只使用系统 UIWindow / UIView，不侵入宿主视图层级。
//
//  唯一对外符号：WGStart()（constructor 里会自动调用，外部无需手动调用）
//

#ifndef WATERMARK_GUARD_H
#define WATERMARK_GUARD_H

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 启动守卫（幂等）。dylib 加载时（constructor）已自动调用，一般无需手动调用。
void WGStart(void);

#ifdef __cplusplus
}
#endif

#endif /* WATERMARK_GUARD_H */
