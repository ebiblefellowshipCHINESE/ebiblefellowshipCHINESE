#!/bin/bash
# 创建 27 个干净的 HTML 文件

# 定义英文书卷名称数组
books=(
  "Matthew"
  "Mark"
  "Luke"
  "John"
  "Acts"
  "Romans"
  "Corinthians-of-1"
  "Corinthians-of-2"
  "Galatians"
  "Ephesians"
  "Philippians"
  "Colossians"
  "Thessalonians-of-1"
  "Thessalonians-of-2"
  "Timothy-of-1"
  "Timothy-of-2"
  "Titus"
  "Philemon"
  "Hebrews"
  "James"
  "Peter-of-1"
  "Peter-of-2"
  "John-of-1"
  "John-of-2"
  "John-of-3"
  "Jude"
  "Revelation"
)

# 遍历数组，为每个书卷创建一个 HTML 文件
for book in "${books[@]}"; do
  cat > "${book}.html" <<EOF

EOF
done

echo "Created ${#books[@]} clean HTML files."
