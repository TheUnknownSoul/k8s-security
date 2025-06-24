#!/usr/bin/env bash
# menu.sh — interactive launcher
# - Arrow-key navigation + Enter
# - TAB-completion for paths + optional picker on 'p' (fzf/dialog/whiptail)
# - Per-script hints, optional validation, confirm-only mode (RBAC)
# - Logs + defaults (~/.myscriptsrc)

# ---------- guards ----------
if [[ -z "${BASH_VERSION:-}" ]]; then exec bash "$0" "$@"; fi
if [[ ! -t 0 || ! -t 1 ]]; then echo "This menu needs an interactive TTY. Run: bash $0" >&2; exit 1; fi


set -uo pipefail
IFS=$'\n\t'

####################
## CONFIG
####################
RC_FILE="$HOME/.myscriptsrc"
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# "Title|type(any text)|path|venv"
SCRIPTS=(
  "Install dependencies |bash installer script|install_dependencies.sh|"
  "Run trivy scanner|bash script|trivy_scan.sh|"
  "Role-based access controll assesment|python script|rbac_check.py|/path/to/venv"
  "Count amount of founded CVE's|python script|CVE_counter.py|/path/to/venv"
  "Get CVE information|python script|CVE_info.py|/path/to/venv"
)

PARAM_HINTS=(
  "No params"
  "Path to folder or file with images to scan. Example: '/path/to/dir' or 'image_hash'. Path is preferable."
  "RBAC check will download and process .json files: roles.json, clusterroles.json, rolebindings.json, clusterrolebindings.json. Requires kubectl."
  "CVE counter: enter folder with Trivy results (saved as previous step)."
  "CVE id e.g. 'CVE-2021-44228' (or leave blank to open interactive lookup)"
)

PARAM_VALIDATION=("" "" "" "" "^CVE-[0-9]{4}-[0-9]{4,}$")

PARAM_PICKER=(
  ""      # 0 Install dependencies
  "file"  # 1 Trivy target
  ""      # 2 RBAC
  "file"  # 3 CVE counter path
  ""      # 4 CVE id
)

RUN_MODE=(
  ""          # 0
  ""          # 1
  "confirm"   # 2 
  ""          # 3
  ""          # 4
)
####################
## END CONFIG
####################

# --- parse + normalize types ---
declare -a TITLES TYPES PATHS VENVS TYPES_RAW
for entry in "${SCRIPTS[@]}"; do
  IFS='|' read -r t tp p v <<< "$entry"
  TITLES+=("$t"); TYPES_RAW+=("$tp"); PATHS+=("$p"); VENVS+=("$v")
done
norm_type() {
  local i="$1" tp_lc path; tp_lc="$(tr '[:upper:]' '[:lower:]' <<<"${TYPES_RAW[i]}")"; path="${PATHS[i]}"
  if [[ "$tp_lc" == *install* ]]; then echo installer
  elif [[ "$tp_lc" == *py* || "$tp_lc" == *python* || "$path" == *.py ]]; then echo py
  else echo bash
  fi
}
for i in "${!TITLES[@]}"; do TYPES+=("$(norm_type "$i")"); done

# --- defaults ---
if [[ -f "$RC_FILE" ]]; then source "$RC_FILE"; fi
if [[ -z "${DEFAULT_PARAMS+x}" ]]; then declare -a DEFAULT_PARAMS; for _ in "${TITLES[@]}"; do DEFAULT_PARAMS+=(""); done; fi
save_rc() {
  cat > "$RC_FILE" <<EOF
# Auto-generated defaults for menu.sh
EOF
  for i in "${!TITLES[@]}"; do p="${DEFAULT_PARAMS[i]//\'/\'\"\'\"\'}"; printf "DEFAULT_PARAMS[%d]='%s'\n" "$i" "$p" >> "$RC_FILE"; done
}
timestamp() { date +"%Y%m%d_%H%M%S"; }

# --- path pickers ---
picker_available() { command -v fzf >/dev/null 2>&1 || command -v dialog >/dev/null 2>&1 || command -v whiptail >/dev/null 2>&1; }
pick_path() {
  local start="${1:-.}"; start="${start/#\~/$HOME}"
  if command -v fzf >/dev/null 2>&1; then
    find -L "$start" -maxdepth 3 -mindepth 1 2>/dev/null \
      | fzf --height=80% --reverse --prompt="Path> " \
            --preview 'ls -la --group-directories-first {} 2>/dev/null || ls -la {} 2>/dev/null' \
            --preview-window=right:60%:wrap
    return 0
  fi
  if command -v dialog >/dev/null 2>&1; then
    local cur out sel; cur="$(realpath -m "$start" 2>/dev/null || echo "$start")"; out=$(mktemp)
    while true; do
      if ! dialog --stdout --title "Select path" --fselect "$cur/" 20 70 >"$out"; then rm -f "$out"; printf ""; return 0; fi
      sel="$(<"$out")"; [[ -z "$sel" ]] && { rm -f "$out"; printf ""; return 0; }
      if [[ -d "$sel" ]]; then cur="$sel"; else rm -f "$out"; printf "%s" "$sel"; return 0; fi
    done
  fi
  if command -v whiptail >/dev/null 2>&1; then
    local cur sel; cur="$(realpath -m "$start" 2>/dev/null || echo "$start")"
    while true; do sel=$(whiptail --title "Select path" --fselect "$cur/" 20 70 3>&1 1>&2 2>&3) || { printf ""; return 0; }
      if [[ -d "$sel" ]]; then cur="$sel"; else printf "%s" "$sel"; return 0; fi
    done
  fi
  # fallback
  local cur entries i sel ans idx; cur="$(realpath -m "$start" 2>/dev/null || echo "$start")"
  while true; do
    echo "Current dir: $cur"; mapfile -t entries < <(ls -1A "$cur" 2>/dev/null || true)
    if ((${#entries[@]}==0)); then read -rp "Enter path manually: " sel; printf "%s" "$sel"; return 0; fi
    for i in "${!entries[@]}"; do [[ -d "$cur/${entries[i]}" ]] && printf "%2d) %s/\n" "$((i+1))" "${entries[i]}" || printf "%2d) %s\n" "$((i+1))" "${entries[i]}"; done
    echo "0) .. (up)   m) manual path   q) cancel"; read -rp "Choose: " ans
    case "$ans" in
      q|Q) printf ""; return 0 ;;
      m|M) read -rp "Path: " sel; printf "%s" "$sel"; return 0 ;;
      0) cur="$(dirname "$cur")" ;;
      ''|*[!0-9]*) echo "Invalid";;
      *) idx=$((ans-1)); [[ $idx -ge 0 && $idx -lt ${#entries[@]} ]] || { echo "Out of range"; continue; }
         sel="$cur/${entries[idx]}"; [[ -d "$sel" ]] && cur="$sel" || { printf "%s" "$sel"; return 0; } ;;
    esac
  done
}


print_banner() {
  local color_on=$'\033[38;5;214m' color_off=$'\033[0m'
  echo -e "${color_on}"
  cat <<'BANNER'
  _  __     _                          _
 | |/ /   _| |__   ___ _ __ _ __   ___| |_ ___  ___
 | ' / | | | '_ \ / _ \ '__| '_ \ / _ \ __/ _ \/ __|
 | . \ |_| | |_) |  __/ |  | | | |  __/ ||  __/\__ \
 |_|\_\__,_|_.__/ \___|_|  |_| |_|\___|\__\___||___/
  ___  ___  ___ _   _ _ __(_) |_ _   _
 / __|/ _ \/ __| | | | '__| | __| | | |
 \__ \  __/ (__| |_| | |  | | |_| |_| |
 |___/\___|\___|\__,_|_|  |_|\__|\__, |
 (_)_ __  ___ _ __   ___  ___| |_|___/ _ __
 | | '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 | | | | \__ \ |_) |  __/ (__| || (_) | |
 |_|_| |_|___/ .__/ \___|\___|\__\___/|_|
             |_|
BANNER
  echo -e "${color_off}"
}

# --- UI ---
options=("${TITLES[@]}" "Show last logs" "Edit config (open editor)" "Exit")
pos=0
DRY_RUN=0

draw_menu() {
  clear
  print_banner
  echo "Interactive tool for k8 security assessment — use ↑ ↓ and Enter."
  echo "---------------------------------------------"
  for i in "${!options[@]}"; do
    [[ "$i" -eq "$pos" ]] && printf " > \e[7m%s\e[0m\n" "${options[$i]}" || printf "   %s\n" "${options[$i]}"
  done
  echo
  echo "Hints: 's' save defaults; 'd' toggle dry-run"
  [[ "$DRY_RUN" -eq 1 ]] && echo "[DRY-RUN ON]"
}


read_input() {
  local key=""
  IFS= read -rsn1 key 2>/dev/null || { echo ""; return 0; }
  if [[ $key == $'\x1b' ]]; then
    local key2=""; read -rsn2 -t 0.001 key2 2>/dev/null || true; key+="$key2"
  fi
  echo "$key"; return 0
}


run_command() {
  local cmd="$1"
  local logf="$2"

  echo "Command: $cmd"
  echo "Log: $logf"

  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    echo "[dry-run] not executing."
    return 0
  fi

  local status=0
  local wrapper rcfile
  wrapper="$(mktemp)"
  rcfile="$(mktemp)"

  
  cat >"$wrapper" <<'EOS'
#!/usr/bin/env bash
set -uo pipefail
# === begin payload ===
EOS
  printf '%s\n' "${cmd}" >>"$wrapper"
  cat >>"$wrapper" <<'EOS'
# === end payload ===
rc=$?
echo "$rc" > __RCFILE__
exit $rc
EOS
  sed -i "s|__RCFILE__|$rcfile|g" "$wrapper"
  chmod +x "$wrapper"

  if command -v script >/dev/null 2>&1 && [[ "${SHELL##*/}" != "zsh" ]]; then
    
    script -q /dev/null -c "bash '$wrapper'" 2>&1 | tee "$logf"
  else
    
    bash "$wrapper" 2>&1 | tee "$logf"
  fi

  if [[ -s "$rcfile" ]]; then
    read -r status < "$rcfile"
  else
    status=${PIPESTATUS[0]:-1}
  fi
  rm -f "$wrapper" "$rcfile"

  echo "Exit status: $status" | tee -a "$logf"
  return "$status"
}




post_run() {
  local status="$1"
  local logf="$2"
  if (( status == 0 )); then
    echo
    echo "Done. Returning to main menu in 5 seconds…"
    sleep 5
  else
    echo
    echo "FAILED (exit $status). Log: $logf"
    echo "----- tail of log -----"
    tail -n 40 "$logf" || true
    echo "-----------------------"
    read -rp "Press Enter to return to menu…" _
  fi
}

build_cmd() {
  local idx=$1
  local params="${2:-}"
  local tp="${TYPES[idx]}"
  local path="${PATHS[idx]}"
  local venv="${VENVS[idx]}"

  if [[ "$tp" == "py" ]]; then
    if [[ -n "$venv" && -d "$venv/bin" ]]; then
      echo "source '$venv/bin/activate' >/dev/null 2>&1; \
py=\$(command -v python || command -v python3); \
if [[ -z \"\$py\" ]]; then echo 'Python interpreter not found: python or python3' >&2; exit 127; fi; \
PYTHONUNBUFFERED=1 \"\$py\" -u '$path' $params"
    else
      echo "py=\$(command -v python || command -v python3); \
if [[ -z \"\$py\" ]]; then echo 'Python interpreter not found: python or python3' >&2; exit 127; fi; \
PYTHONUNBUFFERED=1 \"\$py\" -u '$path' $params"
    fi
  else
    echo "bash '$path' $params"
  fi
}


show_last_logs() {
  echo "Last modified logs in $LOG_DIR:"; ls -1t "$LOG_DIR" 2>/dev/null | sed -n '1,10p' || true
  echo; read -rp "Enter filename to view (or empty to return): " lf
  [[ -n "$lf" && -f "$LOG_DIR/$lf" ]] && less -R "$LOG_DIR/$lf"
}

edit_config() { ${EDITOR:-nano} "${BASH_SOURCE[0]}"; }

trap 'echo "Interrupted. Exiting."; exit 1' INT TERM

# --- Main loop ---
while true; do
  draw_menu
  key="$(read_input)"
  last_index=$(( ${#options[@]} - 1 ))

  case "$key" in
    $'\x1b[A') (( pos > 0 )) && pos=$((pos-1)) || pos=$last_index ;;
    $'\x1b[B') (( pos < last_index )) && pos=$((pos+1)) || pos=0 ;;
    "")
      if [[ $pos -lt ${#TITLES[@]} ]]; then
        idx=$pos; title="${TITLES[idx]}"; type="${TYPES[idx]}"
        clear
        echo "Selected: $title"
        echo "Path: ${PATHS[idx]}"
        echo "Type: $type"
        echo "Default params: ${DEFAULT_PARAMS[idx]}"; echo

        if [[ "$type" == "installer" ]]; then
          read -rp "Run installer now? [Y/n]: " yn; yn=${yn:-Y}
          if [[ $yn =~ ^[Yy] ]]; then
            cmd=$(build_cmd "$idx" "")
            logf="$LOG_DIR/${title}_install_$(timestamp).log"
            run_command "$cmd" "$logf"
            status=$?
            post_run "$status" "$logf"
          fi
        else
          mode="${RUN_MODE[idx]:-}"
          if [[ "$mode" == "confirm" ]]; then
            read -rp "Start RBAC check now? [Y/n]: " yn; yn=${yn:-Y}
            if [[ $yn =~ ^[Yy] ]]; then
              cmd=$(build_cmd "$idx" "")
              logf="$LOG_DIR/${title}_$(timestamp).log"
              run_command "$cmd" "$logf"
              status=$?
              post_run "$status" "$logf"
            else
              echo "Cancelled."; sleep 1
            fi
          else
            hint="${PARAM_HINTS[idx]:-}"; validation="${PARAM_VALIDATION[idx]:-}"
            picker="${PARAM_PICKER[idx]:-}"; picker_ok=0; picker_available && picker_ok=1
            [[ -n "$hint" ]] && { echo; echo "Hint: $hint"; }
            params=""
            while true; do
              if [[ "$picker" == "file" ]]; then
                (( picker_ok )) && echo "(Use TAB for path completion, or type 'p' and Enter to open picker)" \
                                 || echo "(Use TAB for path completion. To enable picker: install 'fzf' or 'dialog')"
                read -e -p "Enter path (leave blank to use default): " userp
              else
                read -rp "Enter parameters (leave blank to use default): " userp
              fi
              if [[ "$picker" == "file" && "$userp" == "p" ]]; then
                if (( picker_ok )); then
                  startdir="${DEFAULT_PARAMS[idx]:-.}"; [[ -z "$startdir" ]] && startdir="."
                  picked="$(pick_path "$startdir")"
                  if [[ -n "$picked" ]]; then params="$picked"; echo "Selected: $params"; break
                  else echo "Picker cancelled."; continue; fi
                else echo "Picker not available. Install 'fzf' or 'dialog' (or use TAB)."; continue; fi
              fi
              if [[ -z "$userp" ]]; then params="${DEFAULT_PARAMS[idx]}"; break; fi
              if [[ -n "$validation" ]]; then
                if [[ "$userp" =~ $validation ]]; then params="$userp"; break
                else echo "Input does not match expected format. Please follow the hint above."
                     [[ "$hint" == *"Example:"* ]] && echo "Example: ${hint#*Example: }"; continue; fi
              else params="$userp"; break; fi
            done
            echo "Params to use: $params"
            read -rp "Save these as default for this script? [y/N]: " saveit
            if [[ $saveit =~ ^[Yy] ]]; then DEFAULT_PARAMS[idx]="$params"; save_rc; echo "Saved."; fi
            echo; read -rp "Options: (r)un now, (d)ry-run toggle, (c)ancel: " opt
            case "$opt" in
              r|R)
                cmd=$(build_cmd "$idx" "$params")
                logf="$LOG_DIR/${title}_$(timestamp).log"
                run_command "$cmd" "$logf"
                status=$?
                post_run "$status" "$logf"
                ;;
              d|D) DRY_RUN=$((1-DRY_RUN)); echo "Dry-run now: $DRY_RUN"; sleep 1 ;;
              *)   echo "Cancelled."; sleep 2 ;;
            esac
          fi
        fi
      else
        lower_index=$((pos - ${#TITLES[@]}))
        case "$lower_index" in
          0) show_last_logs ;;
          1) edit_config ;;
          2) echo "Bye"; exit 0 ;;
        esac
      fi
      ;;
    s|S) save_rc; echo "Defaults saved to $RC_FILE"; sleep 1 ;;
    d|D) DRY_RUN=$((1-DRY_RUN)); echo "Dry-run toggled: $DRY_RUN"; sleep 1 ;;
    q|Q) echo "Exit"; exit 0 ;;
    *) : ;;  
  esac
done
