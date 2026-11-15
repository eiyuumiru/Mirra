#import "environment.h"
#import <Metal/Metal.h>
#import <VideoToolbox/VideoToolbox.h>

typedef struct {
    BOOL received;
    OSStatus status;
    size_t width, height;
} DecodedFrame;

static BOOL valid_access_unit(NSData *sample) {
    const uint8_t *bytes = sample.bytes;
    size_t offset = 0;
    BOOL picture = NO;
    while (offset < sample.length) {
        if (sample.length - offset < 4) return NO;
        uint32_t length = ((uint32_t)bytes[offset] << 24) | ((uint32_t)bytes[offset + 1] << 16)
                        | ((uint32_t)bytes[offset + 2] << 8) | bytes[offset + 3];
        offset += 4;
        if (!length || length > sample.length - offset || (bytes[offset] & 0x80)) return NO;
        uint8_t type = bytes[offset] & 0x1f;
        if (type == 1 || type == 5) picture = YES;
        offset += length;
    }
    return picture;
}

static void decoded(void *context, void *frameContext, OSStatus status, VTDecodeInfoFlags flags,
                    CVImageBufferRef image, CMTime timestamp, CMTime duration) {
    (void)frameContext; (void)flags; (void)timestamp; (void)duration;
    DecodedFrame *frame = context;
    frame->status = status;
    frame->width = image ? CVPixelBufferGetWidth(image) : 0;
    frame->height = image ? CVPixelBufferGetHeight(image) : 0;
    frame->received = YES;
}

static NSDictionary *decoder_gpu(VTDecompressionSessionRef session) {
    CFTypeRef value = NULL;
    OSStatus status = VTSessionCopyProperty(session,
        kVTDecompressionPropertyKey_UsingGPURegistryID, kCFAllocatorDefault, &value);
    NSString *name = nil;
    int64_t identifier = 0;
    if (!status && value && CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue(value, kCFNumberSInt64Type, &identifier) && identifier > 0) {
        for (id<MTLDevice> device in MTLCopyAllDevices()) {
            if (device.registryID == (uint64_t)identifier) { name = device.name; break; }
        }
    }
    if (value) CFRelease(value);
    // Registry IDs are only used for a local match; never export unique IDs.
    return @{@"gpu_query_status": @(status), @"gpu_name": name ?: (id)NSNull.null};
}

static NSDictionary *decode_sample(BOOL requireHardware) {
    // An original 64x64 black Baseline frame encoded with public VideoToolbox.
    // These are SPS/PPS and a four-byte-length-prefixed access unit, not phone data.
    NSData *sps = [[NSData alloc] initWithBase64EncodedString:@"J0LgCqkYhNgLUCAgIwrXvfAQ" options:0];
    NSData *pps = [[NSData alloc] initWithBase64EncodedString:@"KN4JiA==" options:0];
    NSData *sample = [[NSData alloc] initWithBase64EncodedString:
        @"AAAACwYAB4LvBIAAAECAAAAAFQYFEQOH9E7NCkvcoZQ6w9SbFx8AgAAAABMluCAgv//8PRQABBD9999dddeAAAAAEyUS4ICC///w9FAAEEP33311114=" options:0];
    const uint8_t *parameters[] = {sps.bytes, pps.bytes};
    const size_t lengths[] = {sps.length, pps.length};
    CMVideoFormatDescriptionRef format = NULL;
    VTDecompressionSessionRef session = NULL;
    CMBlockBufferRef block = NULL;
    CMSampleBufferRef buffer = NULL;
    DecodedFrame frame = {0};
    NSMutableDictionary *report = [@{@"hardware_required": @(requireHardware),
        @"frame_decoded": @NO, @"using_hardware_acceleration": [NSNull null]} mutableCopy];
    BOOL valid = sps.length > 1 && pps.length > 1 &&
                 (((const uint8_t *)sps.bytes)[0] & 0x1f) == 7 &&
                 (((const uint8_t *)pps.bytes)[0] & 0x1f) == 8 && valid_access_unit(sample);
    report[@"fixture_valid"] = @(valid);
    if (!valid) return report;
    NSDictionary *specification = requireHardware ?
        @{(__bridge NSString *)kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder: @YES} : @{};
    OSStatus status = CMVideoFormatDescriptionCreateFromH264ParameterSets(kCFAllocatorDefault,
        2, parameters, lengths, 4, &format);
    report[@"format_status"] = @(status);
    if (status || !format) goto cleanup;
    VTDecompressionOutputCallbackRecord callback = {decoded, &frame};
    status = VTDecompressionSessionCreate(kCFAllocatorDefault, format,
        (__bridge CFDictionaryRef)specification, NULL, &callback, &session);
    report[@"session_status"] = @(status);
    if (status || !session) goto cleanup;
    CFTypeRef hardware = NULL;
    OSStatus propertyStatus = VTSessionCopyProperty(session,
        kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder, kCFAllocatorDefault, &hardware);
    report[@"hardware_query_status"] = @(propertyStatus);
    if (!propertyStatus && hardware && CFGetTypeID(hardware) == CFBooleanGetTypeID())
        report[@"using_hardware_acceleration"] = @((BOOL)CFBooleanGetValue(hardware));
    if (hardware) CFRelease(hardware);
    status = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, sample.length,
        kCFAllocatorDefault, NULL, 0, sample.length, 0, &block);
    report[@"block_status"] = @(status);
    if (status || !block) goto cleanup;
    status = CMBlockBufferReplaceDataBytes(sample.bytes, block, 0, sample.length);
    report[@"copy_status"] = @(status);
    if (status) goto cleanup;
    CMSampleTimingInfo timing = {CMTimeMake(1, 30), CMTimeMake(0, 30), kCMTimeInvalid};
    size_t sampleSize = sample.length;
    status = CMSampleBufferCreateReady(kCFAllocatorDefault, block, format, 1, 1, &timing, 1, &sampleSize, &buffer);
    report[@"sample_status"] = @(status);
    if (status || !buffer) goto cleanup;
    status = VTDecompressionSessionDecodeFrame(session, buffer, 0, NULL, NULL);
    report[@"submit_status"] = @(status);
    if (status) goto cleanup;
    status = VTDecompressionSessionWaitForAsynchronousFrames(session);
    report[@"wait_status"] = @(status);
    report[@"output_status"] = frame.received ? @(frame.status) : (id)[NSNull null];
    report[@"frame_decoded"] = @((BOOL)(!status && frame.received && !frame.status && frame.width == 64 && frame.height == 64));
cleanup:
    if (session) {
        [report addEntriesFromDictionary:decoder_gpu(session)];
        VTDecompressionSessionInvalidate(session); CFRelease(session);
    }
    if (buffer) CFRelease(buffer);
    if (block) CFRelease(block);
    if (format) CFRelease(format);
    return report;
}

NSDictionary *MirraHostEnvironmentReport(void) {
    NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();
    NSMutableArray *metal = [NSMutableArray array];
    for (id<MTLDevice> device in devices) {
        if (metal.count == 16) break;
        [metal addObject:@{@"name": device.name ?: @"unavailable",
                          @"low_power": @(device.lowPower), @"removable": @(device.removable)}];
    }
    return @{@"schema_version": @1, @"probe": @"host-environment", @"metal_devices": metal,
        @"metal_device_count": @(devices.count), @"h264": @{
            @"sample_profile": @"Baseline", @"sample_width": @64, @"sample_height": @64,
            @"default": decode_sample(NO), @"hardware_required": decode_sample(YES)},
        @"native_mirroring_verified": [NSNull null]};
}
