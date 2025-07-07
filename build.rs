use cfg_expr::targets::{get_builtin_target_by_triple, Os};

fn main() {
    let target = std::env::var("TARGET").unwrap();

    let target = get_builtin_target_by_triple(&target).unwrap();
    if target.os.as_ref().is_some_and(|os| [Os::linux, Os::android].contains(os)) {
        println!("cargo:rustc-cfg=depend_nix");
    }
    if target.os.as_ref().is_some_and(|os| [Os::linux, Os::android, Os::windows].contains(os)) {
        println!("cargo:rustc-cfg=depend_if_addrs");
    }
    else {
        println!("cargo:rustc-cfg=use_fallback_impl");
    }



    println!("cargo::rustc-check-cfg=cfg(depend_nix)");
    println!("cargo::rustc-check-cfg=cfg(depend_if_addrs)");
    println!("cargo::rustc-check-cfg=cfg(use_fallback_impl)");
}