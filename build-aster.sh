#!/usr/bin/env bash

cd $(dirname $0)

app="asterinas"
docker_tag="0.17.2-20260508"

ws="${WS:-1}"
mnt_dir="$(pwd)"

echo ">>> build ${app}"


setting_podman() {
    cat >  /etc/containers/registries.conf << EOF
unqualified-search-registries = ["docker.io"]  # 默认还是搜docker.io
# 重点! 把镜像源地址“附魔”到docker.io前缀上!
[[registry]]
prefix = "docker.io"
location = "docker.1ms.run"       # 毫秒加速, YYDS
[[registry]]
prefix = "docker.io"
location = "hub.rat.dev"          # 鼠鼠快车, 稳
[[registry]]
prefix = "docker.io"
location = "docker.xuanyuan.me"   # 轩辕快递, 使命必达
[[registry]]
prefix = "docker.io"
location = "docker.1panel.live"   # 1Panel专线, 官方认证
EOF
}

do_sync() {
    git remote add github https://github.com/asterinas/asterinas
    git fetch github
    git checkout main       # 或你使用的默认分支 (如 master)
    # git merge github/main   # 合并GitHub 的更改
    # git push origin main    # 推送到 GitLab
}

do_runkernel() {
    if [ -e /dev/kvm ]; then
        make ENABLE_KVM=1 SMP=4 run_kernel
    else
        make ENABLE_KVM=0 SMP=4 run_kernel
    fi
}

do_gdbserver() {
    if [ -e /dev/kvm ]; then
        make ENABLE_KVM=1 SMP=4 gdb_server
    else
        make ENABLE_KVM=0 SMP=4 gdb_server
    fi
}


if [ -n "$1" ]; then
    if [ "$1" == "run_kernel" ]; then
        do_runkernel
    elif [ "$1" == "nixos" ]; then
        make nixos BOOT_PROTOCOL=linux NIXOS_TEST_SUITE=containerization-and-virtualization
    elif [ "$1" == "run_nixos" ]; then
        make run_nixos BOOT_PROTOCOL=linux MEM=2G SMP=2 \
            NIXOS_TEST_SUITE=containerization-and-virtualization NIXOS_TEST_CASE=qemu_display_version
    elif [ "$1" == "gdb_server" ]; then
        do_gdbserver
    elif [ "$1" == "sync" ]; then
        do_sync
    elif [ "$1" == "setting_podman" ]; then
        setting_podman
    fi
    exit 0
fi

docker_id=$(docker ps -a 2>/dev/null | grep -m 1 "asterinas/asterinas" | awk '{print $1}')

if [ -z "$docker_id" ]; then
    docker run -it --privileged --network=host \
        -v /dev:/dev -v $mnt_dir:/root/asterinas  \
        asterinas/asterinas:$docker_tag
else
    is_exited="$(docker ps -a 2>/dev/null | grep -m 1 $docker_id | grep Exited)"
    if [ -n "$is_exited" ]; then
        docker start ${docker_id}
    fi
    docker exec -it ${docker_id} /bin/bash
fi


exit 0
