#!/usr/bin/env bash

# Scan all Docker containers, stop/remove them,
# then remove their images if unused.

set -euo pipefail

echo "=== Current Containers ==="
sudo docker ps -a

echo ""
echo "=== Gathering container IDs ==="

CONTAINERS=$(sudo docker ps -aq)

if [ -z "$CONTAINERS" ]; then
    echo "No containers found."
    exit 0
fi

echo ""
echo "=== Stopping Containers ==="
for c in $CONTAINERS; do
    NAME=$(sudo docker inspect --format '{{.Name}}' "$c" | sed 's#^/##')
    IMAGE=$(sudo docker inspect --format '{{.Config.Image}}' "$c")

    echo "Stopping: $NAME ($IMAGE)"
    sudo docker stop "$c" || true
done

echo ""
echo "=== Removing Containers ==="
for c in $CONTAINERS; do
    NAME=$(sudo docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's#^/##' || true)

    echo "Removing: ${NAME:-$c}"
    sudo docker rm -f "$c" || true
done

echo ""
echo "=== Removing Unused Images ==="

IMAGES=$(sudo docker images -q | sort -u)

for img in $IMAGES; do
    TAG=$(sudo docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | grep "$img" | head -1 | awk '{print $1}')

    echo "Removing image: $TAG"
    sudo docker rmi -f "$img" || true
done

echo ""
echo "=== Final State ==="

echo "--- Containers ---"
sudo docker ps -a

echo ""
echo "--- Images ---"
sudo docker images
