#!/usr/bin/env bash

# Host checks that guard a timed paper-v1 run.
# These helpers only observe the host; memory use is not gated.

# Measure currently available memory, including any cgroup limit, for the
# provenance record written by report.sh.
effective_available_memory_kib() {
  local available_kib cgroup_limit_bytes cgroup_used_bytes cgroup_available_kib
  available_kib="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
  [[ "$available_kib" =~ ^[0-9]+$ ]] || pir_die "could not read MemAvailable"
  if [[ -r /sys/fs/cgroup/memory.max && -r /sys/fs/cgroup/memory.current ]]; then
    cgroup_limit_bytes="$(< /sys/fs/cgroup/memory.max)"
    cgroup_used_bytes="$(< /sys/fs/cgroup/memory.current)"
    if [[ "$cgroup_limit_bytes" =~ ^[0-9]+$ && "$cgroup_used_bytes" =~ ^[0-9]+$ ]]; then
      if ((cgroup_used_bytes >= cgroup_limit_bytes)); then
        cgroup_available_kib=0
      else
        cgroup_available_kib=$(((cgroup_limit_bytes - cgroup_used_bytes) / 1024))
      fi
      ((cgroup_available_kib < available_kib)) && available_kib="$cgroup_available_kib"
    fi
  fi
  printf '%s\n' "$available_kib"
}

cpu_governors() {
  local governor_file governors=""
  for governor_file in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
    [[ -r "$governor_file" ]] || continue
    governors+="$(< "$governor_file"),"
  done
  printf '%s\n' "${governors%,}"
}

cpu_boost_state() {
  local value
  if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    value="$(< /sys/devices/system/cpu/intel_pstate/no_turbo)"
    [[ "$value" == "0" ]] && printf 'enabled\n' || printf 'disabled\n'
  elif [[ -r /sys/devices/system/cpu/cpufreq/boost ]]; then
    value="$(< /sys/devices/system/cpu/cpufreq/boost)"
    [[ "$value" == "1" ]] && printf 'enabled\n' || printf 'disabled\n'
  else
    printf 'unavailable\n'
  fi
}

# Memory is not gated: actual usage depends on the layout, profile and host.
# A formal run still requires a pinned CPU set and the performance governor.
pir_check_runtime() {
  local governors
  if [[ "${PIR_FORMAL_RUN:-0}" == "1" && -z "$CPU_SET" ]]; then
    pir_die "formal run requires an explicit --cpu-set to prevent CPU migration"
  fi
  governors="$(cpu_governors)"
  printf 'cpu_boost=%s\n' "$(cpu_boost_state)"
  if [[ "${PIR_FORMAL_RUN:-0}" == "1" && -n "$governors" && ! "$governors" =~ ^performance(,performance)*$ ]]; then
    if [[ "${PIR_ALLOW_UNSTABLE_CPU:-0}" != "1" ]]; then
      pir_die "formal run requires the performance CPU governor; runner will not change it automatically"
    fi
    printf 'warning: formal run is using non-performance CPU governors: %s\n' "$governors" >&2
  fi
}
