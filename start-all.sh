#!/usr/bin/env bash

# ==============================================================================
# SWYRA M Auth — Local Development Multi-Server Starter
# ==============================================================================
# Starts all services concurrently:
#   1. Hono Backend API             -> http://localhost:3000
#   2. Auth Gateway & Admin UI      -> http://localhost:5174
#   3. Next.js Consumer App         -> http://localhost:3001
#   4. Consumer Express Backend     -> http://localhost:4000
#   5. Consumer React Frontend      -> http://localhost:5175
# ==============================================================================

# Determine root repository directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define service paths
HONO_DIR="$ROOT_DIR/hono"
FRONTEND_DIR="$ROOT_DIR/frontend"
NEXT_APP_DIR="$ROOT_DIR/test/next-app"
CONSUMER_BE_DIR="$ROOT_DIR/test/react-express-app/backend"
CONSUMER_FE_DIR="$ROOT_DIR/test/react-express-app/frontend"

# ANSI Color Codes
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
MAGENTA="\033[1;35m"
BLUE="\033[1;34m"
RED="\033[1;31m"
BOLD="\033[1m"
NC="\033[0m" # No Color

# Track background process IDs
PIDS=()

# ── Cleanup & Graceful Shutdown Handler ───────────────────────────────────────
cleanup() {
  trap - SIGINT SIGTERM EXIT
  echo ""
  echo -e "${YELLOW}🛑 Shutting down all development servers...${NC}"
  
  for pid in "${PIDS[@]}"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      # Terminate child processes first
      pkill -P "$pid" 2>/dev/null || true
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done

  # Kill any remaining background subjobs
  kill $(jobs -p) 2>/dev/null || true
  wait 2>/dev/null || true
  
  echo -e "${GREEN}✅ All servers stopped successfully.${NC}"
  exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# ── Pre-flight Checks ────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "======================================================================"
echo "  🚀 SWYRA M Auth — Starting All Development Servers"
echo "======================================================================"
echo -e "${NC}"

# Check for required tools
if ! command -v node >/dev/null 2>&1; then
  echo -e "${RED}❌ Error: Node.js is not installed or not in PATH.${NC}"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo -e "${RED}❌ Error: npm is not installed or not in PATH.${NC}"
  exit 1
fi

# Function to check dependencies
check_dependencies() {
  local name="$1"
  local dir="$2"

  if [ ! -d "$dir" ]; then
    echo -e "${RED}❌ Error: Directory not found: $dir${NC}"
    exit 1
  fi

  if [ ! -d "$dir/node_modules" ]; then
    echo -e "${YELLOW}📦 Installing dependencies in $name ($dir)...${NC}"
    (cd "$dir" && npm install)
  fi
}

# Check port availability helper
check_port() {
  local port="$1"
  local service_name="$2"
  if command -v lsof >/dev/null 2>&1; then
    local pid
    pid=$(lsof -ti:"$port" 2>/dev/null | head -n 1)
    if [ -n "$pid" ]; then
      echo -e "${YELLOW}⚠️  Warning: Port $port ($service_name) is already in use by PID $pid.${NC}"
    fi
  fi
}

echo -e "${BLUE}🔍 Checking dependencies and ports...${NC}"
check_dependencies "Hono Backend" "$HONO_DIR"
check_dependencies "Auth Frontend" "$FRONTEND_DIR"
check_dependencies "Next.js Consumer App" "$NEXT_APP_DIR"
check_dependencies "Consumer Express Backend" "$CONSUMER_BE_DIR"
check_dependencies "Consumer React Frontend" "$CONSUMER_FE_DIR"

check_port 3000 "Hono API"
check_port 5174 "Auth Frontend"
check_port 3001 "Next.js App"
check_port 4000 "Express Backend"
check_port 5175 "React Frontend"

echo ""
echo -e "${BOLD}📋 Active Service Endpoints:${NC}"
echo -e "  🔐 ${CYAN}1. Hono Backend (IdP Core):${NC}         http://localhost:3000"
echo -e "  🎨 ${GREEN}2. SWYRA Auth UI (Gateway / Admin):${NC} http://localhost:5174"
echo -e "  ⚡ ${YELLOW}3. Next.js Consumer App:${NC}            http://localhost:3001"
echo -e "  ⚙️  ${MAGENTA}4. Consumer Express Backend:${NC}         http://localhost:4000"
echo -e "  💻 ${BLUE}5. Consumer React Frontend:${NC}          http://localhost:5175"
echo ""
echo -e "${YELLOW}💡 Press [Ctrl + C] at any time to stop all servers simultaneously.${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo ""

# ── Service Launcher with Prefix Multiplexing ────────────────────────────────
start_service() {
  local label="$1"
  local color="$2"
  local dir="$3"
  local cmd="$4"

  (
    cd "$dir" || exit 1
    $cmd 2>&1 | while IFS= read -r line; do
      printf "${color}[%-10s]${NC} %s\n" "$label" "$line"
    done
  ) &
  
  PIDS+=($!)
}

# 1. Start Hono Backend (:3000)
start_service "HONO:3000" "$CYAN" "$HONO_DIR" "npm run dev"

# 2. Start Auth Frontend (:5174)
start_service "AUTH:5174" "$GREEN" "$FRONTEND_DIR" "npm run dev"

# 3. Start Next.js Consumer App (:3001)
start_service "NEXT:3001" "$YELLOW" "$NEXT_APP_DIR" "npm run dev"

# 4. Start Consumer Express Backend (:4000)
start_service "EXPR:4000" "$MAGENTA" "$CONSUMER_BE_DIR" "npm run dev"

# 5. Start Consumer React Frontend (:5175)
start_service "REACT:5175" "$BLUE" "$CONSUMER_FE_DIR" "npm run dev"

# Keep script running and wait for background processes
wait
