mod image;
mod opencv;
mod test;

use crate::{commands::fetch_online, Arch, PROJECT_DIR, REPOS};
use os_xtask_utils::{dir, CommandExt, Ext, Git, Make};
use std::{
    env,
    ffi::OsString,
    fs,
    os::unix,
    path::{Path, PathBuf},
};

pub(crate) struct LinuxRootfs(Arch);

impl LinuxRootfs {
    /// 生成指定架构的 linux rootfs 操作对象。
    #[inline]
    pub const fn new(arch: Arch) -> Self {
        Self(arch)
    }

    /// 构造启动内存文件系统 rootfs。
    /// 对于 x86_64，这个文件系统可用于 libos 启动。
    /// 若设置 `clear`，将清除已存在的目录。
    pub fn make(&self, clear: bool) {
        // 若已存在且不需要清空，可以直接退出
        let dir = self.path();
        if dir.is_dir() && !clear {
            return;
        }
        // 准备最小系统需要的资源
        let musl = self.0.linux_musl_cross();
        let busybox = self.busybox(&musl);
        // 拷贝 apk
        let bin = dir.join("bin");
        let lib = dir.join("lib");
        dir::clear(&dir).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&lib).unwrap();

        let apk = self.apk(&musl);
        if apk.is_file() {
            fs::copy(&apk, bin.join("apk")).unwrap();
            let etc = dir.join("etc");
            let etc_apk = etc.join("apk");
            fs::create_dir_all(&etc_apk).unwrap();
            fs::write(
                etc_apk.join("repositories"),
                "http://dl-cdn.alpinelinux.org/alpine/v3.23/main\nhttp://dl-cdn.alpinelinux.org/alpine/v3.23/community\n",
            )
            .unwrap();
            fs::write(etc_apk.join("world"), "").unwrap();

            // Add DNS resolution
            fs::write(
                etc.join("resolv.conf"),
                "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
            )
            .unwrap();
            let lib_apk = dir.join("lib").join("apk");
            fs::create_dir_all(&lib_apk).unwrap();
            let lib_apk_db = lib_apk.join("db");
            fs::create_dir_all(&lib_apk_db).unwrap();
            fs::write(lib_apk_db.join("installed"), "").unwrap();

            let var_lib = dir.join("var").join("lib");
            fs::create_dir_all(&var_lib).unwrap();
            #[cfg(unix)]
            let _ = unix::fs::symlink("../../lib/apk", var_lib.join("apk"));

            let var_cache_apk = dir.join("var").join("cache").join("apk");
            fs::create_dir_all(&var_cache_apk).unwrap();
        }

        // 拷贝 busybox
        fs::copy(busybox, bin.join("busybox")).unwrap();
        // 拷贝 dhcpcd
        let dhcpcd = self.dhcpcd(&musl);
        if dhcpcd.is_file() {
            fs::copy(&dhcpcd, bin.join("dhcpcd")).unwrap();
            
            // 拷贝 dhcpcd 配置和 hooks
            let dhcpcd_dir = PROJECT_DIR.join("tools").join("dhcpcd");
            let etc = dir.join("etc");
            fs::copy(dhcpcd_dir.join("src/dhcpcd.conf"), etc.join("dhcpcd.conf")).unwrap();
            
            let lib_dhcpcd = dir.join("lib").join("dhcpcd");
            let hooks_dir = lib_dhcpcd.join("dhcpcd-hooks");
            fs::create_dir_all(&hooks_dir).unwrap();
            fs::copy(dhcpcd_dir.join("hooks/dhcpcd-run-hooks"), lib_dhcpcd.join("dhcpcd-run-hooks")).unwrap();
            // Do NOT install hook scripts into dhcpcd-hooks/ — they depend on sysctl,
            // resolvconf, hostname, and /proc/sys/kernel/hostname which are not yet
            // implemented in Eclipse OS. When hooks fail with exit 127 dhcpcd reports
            // a script error and times out.  The empty hook directory means
            // dhcpcd-run-hooks sources nothing and exits cleanly.

            // Create directories for dhcpcd runtime files
            let var_run_dhcpcd = dir.join("var/run/dhcpcd");
            fs::create_dir_all(&var_run_dhcpcd).unwrap();
            let var_lib_dhcpcd = dir.join("var/lib/dhcpcd");
            fs::create_dir_all(&var_lib_dhcpcd).unwrap();

            // /run/dhcpcd — dhcpcd control socket lives here by default
            let run_dhcpcd = dir.join("run/dhcpcd");
            fs::create_dir_all(&run_dhcpcd).unwrap();

            // Write a minimal dhcpcd.conf — always overwrite to ensure hooks are disabled.
            // This lets us test if dhcpcd progresses past PREINIT without the hook layer.
            let etc = dir.join("etc");
            fs::create_dir_all(&etc).unwrap();
            let dhcpcd_conf = etc.join("dhcpcd.conf");
            fs::write(&dhcpcd_conf,
                b"# Eclipse OS dhcpcd configuration\n\
                  # Disable ALL hooks -- Eclipse OS does not support the full hook layer yet\n\
                  nohook *\n\
                  nodev\n\
                  broadcast\n\
                  timeout 30\n\
                  reboot 5\n"
            ).unwrap();
        }

        // /etc/machine-id — prevents dhcp_vendor "No such file or directory"
        let machine_id = dir.join("etc/machine-id");
        if !machine_id.exists() {
            fs::write(&machine_id, b"eclipseoseclipseoseclipseoseclip\n").unwrap();
        }

        // 拷贝 libc.so
        let from = musl
            .join(format!("{}-linux-musl", self.0.name()))
            .join("lib")
            .join("libc.so");
        let to = lib.join(format!("ld-musl-{arch}.so.1", arch = self.0.name()));
        fs::copy(from, &to).unwrap();
        Ext::new(self.strip(&musl)).arg("-s").arg(to).invoke();
        // 为 busybox 支持的所有 applets 建立符号链接
        let bin = dir.join("bin");
        let busybox_bin = bin.join("busybox");
        
        // Base list of essential applets
        let mut applets: Vec<String> = vec![
            "cat", "cp", "echo", "false", "grep", "gzip", "ip", "kill",
            "ln", "ls", "mkdir", "mv", "pidof", "ping", "ps", "pwd", "rm", 
            "rmdir", "sh", "sleep", "stat", "tar", "touch", "true", "uname", 
            "usleep", "watch", "ifconfig", "route", "udhcpc", "udhcpc6", 
            "sed", "awk", "cmp", "diff", "logger", "hostname", "cut", "sort", 
            "uniq", "head", "tail", "wc", "xargs", "find", "test", "expr", 
            "id", "date", "env", "chmod", "chown", "vi", "top", "less"
        ].into_iter().map(String::from).collect();

        // Try to complement the list with busybox --list if it can run on host
        if let Ok(out) = std::process::Command::new(&busybox_bin).arg("--list").output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    for line in s.lines() {
                        let applet = line.trim().to_string();
                        if !applet.is_empty() && !applets.contains(&applet) {
                            applets.push(applet);
                        }
                    }
                }
            }
        }

        for applet in &applets {
            let link = bin.join(applet);
            if !link.exists() && !link.is_symlink() {
                let _ = unix::fs::symlink("busybox", &link);
            }
        }
        // Create standard pseudo-filesystem mount points
        let _ = fs::create_dir_all(dir.join("run"));
        let _ = fs::create_dir_all(dir.join("proc"));
        let _ = fs::create_dir_all(dir.join("sys"));
        let _ = fs::create_dir_all(dir.join("tmp"));
        let _ = fs::create_dir_all(dir.join("dev"));

        // udhcpc default script — applies the DHCP-acquired address
        let udhcpc_dir = dir.join("usr/share/udhcpc");
        fs::create_dir_all(&udhcpc_dir).unwrap();
        let udhcpc_script = udhcpc_dir.join("default.script");
        fs::write(&udhcpc_script,
            b"#!/bin/sh\n\
              # Minimal udhcpc script for Eclipse OS\n\
              case \"$1\" in\n\
                deconfig)\n\
                  ip addr flush dev $interface 2>/dev/null\n\
                  ifconfig $interface 0.0.0.0 up 2>/dev/null\n\
                  ;;\n\
                bound|renew)\n\
                  ifconfig $interface $ip netmask ${subnet:-255.255.255.0} up 2>/dev/null\n\
                  if [ -n \"$router\" ]; then\n\
                    for r in $router; do\n\
                      route add default gw $r dev $interface 2>/dev/null\n\
                    done\n\
                  fi\n\
                  if [ -n \"$dns\" ]; then\n\
                    echo -n > /etc/resolv.conf\n\
                    for d in $dns; do\n\
                      echo \"nameserver $d\" >> /etc/resolv.conf\n\
                    done\n\
                  fi\n\
                  ;;\n\
              esac\n"
        ).unwrap();
        // Make the script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&udhcpc_script, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // 拷贝 nl_dump (netlink dump helper).
        // Do this AFTER symlink creation to ensure it's a real binary, not a BusyBox link.
        let nl_dump = self.nl_dump(&musl);
        if nl_dump.is_file() {
            let dst = bin.join("nl_dump");
            let _ = dir::rm(&dst);
            fs::copy(&nl_dump, &dst).unwrap();
        }

        // 拷贝 edhcpc (Eclipse DHCPv4 client).
        // This is a static, minimal DHCPv4 client that uses rtnetlink to apply IP/gw.
        let edhcpc = self.edhcpc(&musl);
        if edhcpc.is_file() {
            let dst = bin.join("edhcpc");
            let _ = dir::rm(&dst);
            fs::copy(&edhcpc, &dst).unwrap();
        }
    }

    /// 将 musl 动态库放入 rootfs。
    pub fn put_musl_libs(&self) -> PathBuf {
        // 递归 rootfs
        self.make(false);
        let dir = self.0.linux_musl_cross();
        self.put_libs(&dir, dir.join(format!("{}-linux-musl", self.0.name())));
        dir
    }

    /// 指定架构的 rootfs 路径。
    #[inline]
    pub fn path(&self) -> PathBuf {
        PROJECT_DIR.join("rootfs").join(self.0.name())
    }

    /// 编译 busybox。
    fn busybox(&self, musl: impl AsRef<Path>) -> PathBuf {
        // 最终文件路径
        let target = self.0.target().join("busybox");
        // 如果文件存在，直接退出
        let executable = target.join("busybox");
        if executable.is_file() {
            return executable;
        }
        // 获得源码
        let source = REPOS.join("busybox");
        if !source.is_dir() {
            fetch_online!(source, |tmp| {
                Git::clone("https://git.busybox.net/busybox.git")
                    .dir(tmp)
                    .single_branch()
                    .depth(1)
                    .done()
            });
        }
        // 拷贝
        dir::rm(&target).unwrap();
        dircpy::copy_dir(source, &target).unwrap();
        // 配置
        Make::new().current_dir(&target).arg("defconfig").invoke();
        // Force static linking and disable PIE (Type EXEC is more stable in zCore)
        Ext::new("sed")
            .current_dir(&target)
            .arg("-i")
            .arg("s/.*CONFIG_STATIC.*/CONFIG_STATIC=y/\
                  s/.*CONFIG_PIE.*/CONFIG_PIE=n/\
                  s/.*CONFIG_FEATURE_INDIVIDUAL.*/CONFIG_FEATURE_INDIVIDUAL=n/\
                  s/.*CONFIG_FEATURE_SHARED_BUSYBOX.*/CONFIG_FEATURE_SHARED_BUSYBOX=n/")
            .arg(".config")
            .invoke();

        // 编译
        let musl = musl.as_ref().canonicalize().unwrap();
        let cross_compile = format!(
            "{musl}/bin/{arch}-linux-musl-",
            musl = musl.display(),
            arch = self.0.name(),
        );
        
        Make::new()
            .current_dir(&target)
            .arg(format!("CROSS_COMPILE={cross_compile}"))
            .arg("LDFLAGS=-static -no-pie")
            .arg("EXTRA_LDFLAGS=-static -no-pie")
            .arg("CFLAGS=-fno-PIC -fno-PIE")
            .arg("EXTRA_CFLAGS=-fno-PIC -fno-PIE")
            .arg("CONFIG_STATIC=y")
            .arg("CONFIG_PIE=n")
            .invoke();
        // 裁剪
        Ext::new(self.strip(musl))
            .arg("-s")
            .arg(&executable)
            .invoke();
        executable
    }

    /// 编译 apk-tools。
    fn apk(&self, musl: &Path) -> PathBuf {
        let apk_dir = PROJECT_DIR.join("tools").join("apk");
        let bld_dir = apk_dir.join("bld-eclipse");
        let executable = bld_dir.join("src/apk");

        if executable.is_file() {
            return executable;
        }

        println!("Compiling apk-tools...");
        // Try to compile
        let mut res = Ext::new("meson")
            .current_dir(&apk_dir)
            .arg("compile")
            .arg("-C")
            .arg("bld-eclipse")
            .status();

        if !res.success() {
            println!("Initial compile failed, trying to re-setup meson...");
            dir::rm(&bld_dir).unwrap();
            let cross_file = self.generate_apk_cross_file(musl);

            Ext::new("meson")
                .current_dir(&apk_dir)
                .arg("setup")
                .arg("bld-eclipse")
                .arg("--cross-file")
                .arg(&cross_file)
                .arg("-Dminimal=true")
                .arg("-Dcrypto_backend=mbedtls")
                .arg("-Durl_backend=libfetch")
                .arg("-Dlua=disabled")
                .arg("-Dpython=disabled")
                .arg("-Dzstd=disabled")
                .arg("-Dtests=disabled")
                .invoke();

            res = Ext::new("meson")
                .current_dir(&apk_dir)
                .arg("compile")
                .arg("-C")
                .arg("bld-eclipse")
                .status();
        }

        if !res.success() {
            println!("Failed to compile apk");
        }

        executable
    }

    fn generate_apk_cross_file(&self, musl: &Path) -> PathBuf {
        let path = self.0.target().join("meson.cross-apk");
        let musl_bin = musl.canonicalize().unwrap().join("bin");
        let arch = self.0.name();
        let cpu_family = if arch == "x86_64" { "x86_64" } else { arch };

        let zlib_path = PROJECT_DIR.join("tools").join("zlib");
        let mbedtls_path = PROJECT_DIR.join("tools").join("mbedtls");

        let content = format!(
            r#"[binaries]
c = '{bin}/{arch}-linux-musl-gcc'
cpp = '{bin}/{arch}-linux-musl-g++'
ar = '{bin}/{arch}-linux-musl-gcc-ar'
nm = '{bin}/{arch}-linux-musl-gcc-nm'
ranlib = '{bin}/{arch}-linux-musl-gcc-ranlib'
strip = '{bin}/{arch}-linux-musl-strip'

[host_machine]
system = 'linux'
cpu_family = '{cpu_family}'
cpu = '{arch}'
endian = 'little'

[built-in options]
c_args = ['-static', '-I{zlib}', '-I{mbedtls}/include']
cpp_args = ['-static', '-I{zlib}', '-I{mbedtls}/include']
c_link_args = ['-static', '-L{zlib}', '-L{mbedtls}/bld-eclipse/library', '-lz', '-lmbedcrypto', '-lmbedtls', '-lmbedx509']
cpp_link_args = ['-static', '-L{zlib}', '-L{mbedtls}/bld-eclipse/library', '-lz', '-lmbedcrypto', '-lmbedtls', '-lmbedx509']
"#,
            bin = musl_bin.display(),
            arch = arch,
            cpu_family = cpu_family,
            zlib = zlib_path.display(),
            mbedtls = mbedtls_path.display()
        );
        fs::write(&path, content).unwrap();
        path
    }

    /// 编译 dhcpcd。
    fn dhcpcd(&self, musl: &Path) -> PathBuf {
        let dhcpcd_dir = PROJECT_DIR.join("tools").join("dhcpcd");
        let executable = dhcpcd_dir.join("src/dhcpcd");

        if executable.is_file() {
            return executable;
        }

        println!("Compiling dhcpcd...");
        let musl = musl.canonicalize().unwrap();
        let bin = musl.join("bin");
        let arch = self.0.name();

        // 尝试编译
        let mut res = Ext::new("./configure")
            .current_dir(&dhcpcd_dir)
            .env("CC", format!("{}/{}-linux-musl-gcc", bin.display(), arch))
            .arg("--prefix=")
            .arg("--sbindir=/bin")
            .arg("--sysconfdir=/etc")
            .arg("--dbdir=/var/lib/dhcpcd")
            .arg("--libexecdir=/lib/dhcpcd")
            .arg("--disable-privsep")
            .arg("--without-dev")
            .status();

        if res.success() {
            res = Make::new().current_dir(&dhcpcd_dir).status();
        }

        if !res.success() {
            println!("Failed to compile dhcpcd");
        } else {
            // 裁剪
            Ext::new(self.strip(&musl))
                .arg("-s")
                .arg(&executable)
                .invoke();
        }

        executable
    }

    /// 编译 nl_dump (static netlink dump helper).
    fn nl_dump(&self, musl: &Path) -> PathBuf {
        let dir = PROJECT_DIR.join("tools").join("nl_dump");
        let executable = dir.join("nl_dump");
        let source = dir.join("nl_dump.c");
        // Rebuild if missing or if source is newer than the binary.
        if executable.is_file() && source.is_file() {
            if let (Ok(bin_meta), Ok(src_meta)) = (fs::metadata(&executable), fs::metadata(&source))
            {
                if let (Ok(bin_mtime), Ok(src_mtime)) = (bin_meta.modified(), src_meta.modified())
                {
                    if bin_mtime >= src_mtime {
                        return executable;
                    }
                }
            }
        }

        println!("Compiling nl_dump...");
        let musl = musl.canonicalize().unwrap();
        let bin = musl.join("bin");
        let arch = self.0.name();
        let cc = format!("{}/{}-linux-musl-gcc", bin.display(), arch);
        let strip = self.strip(&musl);

        fs::create_dir_all(&dir).unwrap();
        let status = Ext::new(&cc)
            .current_dir(&dir)
            .arg("-static")
            .arg("-O2")
            .arg("-s")
            .arg("-o")
            .arg(&executable)
            .arg(&source)
            .status();
        if !status.success() {
            println!("Failed to compile nl_dump");
            return executable;
        }

        Ext::new(strip).arg("-s").arg(&executable).status();
        executable
    }

    /// 编译 edhcpc (static DHCPv4 client for Eclipse OS).
    fn edhcpc(&self, musl: &Path) -> PathBuf {
        let dir = PROJECT_DIR.join("tools").join("edhcpc");
        let executable = dir.join("edhcpc");
        let source = dir.join("edhcpc.c");
        // Rebuild if missing or if source is newer than the binary.
        if executable.is_file() && source.is_file() {
            if let (Ok(bin_meta), Ok(src_meta)) = (fs::metadata(&executable), fs::metadata(&source))
            {
                if let (Ok(bin_mtime), Ok(src_mtime)) = (bin_meta.modified(), src_meta.modified())
                {
                    if bin_mtime >= src_mtime {
                        return executable;
                    }
                }
            }
        }

        println!("Compiling edhcpc...");
        let musl = musl.canonicalize().unwrap();
        let bin = musl.join("bin");
        let arch = self.0.name();
        let cc = format!("{}/{}-linux-musl-gcc", bin.display(), arch);
        let strip = self.strip(&musl);

        fs::create_dir_all(&dir).unwrap();
        let status = Ext::new(&cc)
            .current_dir(&dir)
            .arg("-static")
            .arg("-O2")
            .arg("-s")
            .arg("-o")
            .arg(&executable)
            .arg(&source)
            .status();
        if !status.success() {
            println!("Failed to compile edhcpc");
            return executable;
        }

        Ext::new(strip).arg("-s").arg(&executable).status();
        executable
    }

    fn strip(&self, musl: impl AsRef<Path>) -> PathBuf {
        musl.as_ref()
            .join("bin")
            .join(format!("{}-linux-musl-strip", self.0.name()))
    }

    /// 从安装目录拷贝所有 so 和 so 链接到 rootfs
    fn put_libs(&self, musl: impl AsRef<Path>, dir: impl AsRef<Path>) {
        let lib = self.path().join("lib");
        let musl_libc_protected = format!("ld-musl-{}.so.1", self.0.name());
        let musl_libc_ignored = "libc.so";
        let strip = self.strip(musl);
        dir.as_ref()
            .join("lib")
            .read_dir()
            .unwrap()
            .filter_map(|res| res.map(|e| e.path()).ok())
            .filter(|path| check_so(path))
            .for_each(|source| {
                let name = source.file_name().unwrap();
                let target = lib.join(name);
                if source.is_symlink() {
                    if name != musl_libc_protected.as_str() {
                        dir::rm(&target).unwrap();
                        // `fs::copy` 会拷贝文件内容
                        unix::fs::symlink(source.read_link().unwrap(), target).unwrap();
                    }
                } else if name != musl_libc_ignored {
                    dir::rm(&target).unwrap();
                    fs::copy(source, &target).unwrap();
                    Ext::new(&strip).arg("-s").arg(target).status();
                }
            });
    }
}

/// 为 PATH 环境变量附加路径。
fn join_path_env<I, S>(paths: I) -> OsString
where
    I: IntoIterator<Item = S>,
    S: AsRef<Path>,
{
    let mut path = OsString::new();
    let mut first = true;
    if let Ok(current) = env::var("PATH") {
        path.push(current);
        first = false;
    }
    for item in paths {
        if first {
            first = false;
        } else {
            path.push(":");
        }
        path.push(item.as_ref().canonicalize().unwrap().as_os_str());
    }
    path
}

/// 判断一个文件是动态库或动态库的符号链接。
fn check_so<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    // 是符号链接或文件
    // 对于符号链接，`is_file` `exist` 等函数都会针对其指向的真实文件判断
    if !path.is_symlink() && !path.is_file() {
        return false;
    }
    // 对文件名分段
    let name = path.file_name().unwrap().to_string_lossy();
    let mut seg = name.split('.');
    // 不能以 . 开头
    if matches!(seg.next(), Some("") | None) {
        return false;
    }
    // 扩展名的第一项是 so
    if !matches!(seg.next(), Some("so")) {
        return false;
    }
    // so 之后全是纯十进制数字
    !seg.any(|it| !it.chars().all(|ch| ch.is_ascii_digit()))
}
