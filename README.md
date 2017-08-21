------------------------------------------
Error while building Linux kernel bindings
------------------------------------------

STD_KERNEL_PATH='/lib/modules/4.2.0-41-generic/build' cargo build
   Compiling kernel-wrapper v0.1.0 (file:///local/mnt/workspace/dipanjan/kwrap)
error: failed to run custom build command for `kernel-wrapper v0.1.0 (file:///local/mnt/workspace/dipanjan/kwrap)`
process didn't exit successfully: `/local/mnt/workspace/dipanjan/kwrap/target/debug/build/kernel-wrapper-abf16a8eacafefd0/build-script-build` (exit code: 101)
--- stdout
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:142:6: error: variable has incomplete type 'void', err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:142:12: error: expected ';' after top level declarator, err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:143:11: error: expected ';' after top level declarator, err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:281:6: error: variable has incomplete type 'void', err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:281:12: error: expected ';' after top level declarator, err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:282:6: error: variable has incomplete type 'void', err: true
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:282:12: error: expected ';' after top level declarator, err: true
/lib/modules/4.2.0-41-generic/build/include/linux/linkage.h:7:10: fatal error: 'asm/linkage.h' file not found, err: true

--- stderr
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:142:6: error: variable has incomplete type 'void'
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:142:12: error: expected ';' after top level declarator
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:143:11: error: expected ';' after top level declarator
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:281:6: error: variable has incomplete type 'void'
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:281:12: error: expected ';' after top level declarator
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:282:6: error: variable has incomplete type 'void'
/lib/modules/4.2.0-41-generic/build/include/linux/init.h:282:12: error: expected ';' after top level declarator
/lib/modules/4.2.0-41-generic/build/include/linux/linkage.h:7:10: fatal error: 'asm/linkage.h' file not found
thread 'main' panicked at 'Unable to generate kernel bindings: ()', /checkout/src/libcore/result.rs:859
note: Run with `RUST_BACKTRACE=1` for a backtrace.

make: *** [all] Error 101
