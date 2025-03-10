import tkinter as tk
from tkinter import simpledialog, scrolledtext

def input_chapters():
    chapters = []
    # 弹出对话框获取用户要生成的章数（最小值为1）
    num_chapters = simpledialog.askinteger("生成章节", "请输入要生成的章数：", minvalue=1)
    if num_chapters is None:
        return None

    # 针对每一章依次弹出输入窗口
    for i in range(1, num_chapters + 1):
        dialog = tk.Toplevel(root)
        dialog.title(f"创世纪第 {i} 章输入")
        # 提示信息
        label = tk.Label(dialog, text=f"请输入创世纪第 {i} 章的经文内容（每行代表一节，经文输入完毕后请点击确定按钮）：")
        label.pack(padx=10, pady=10)
        # 多行文本输入框
        text_widget = tk.Text(dialog, width=60, height=15)
        text_widget.pack(padx=10, pady=10)
        # 确定按钮，点击后关闭当前窗口
        confirm_button = tk.Button(dialog, text="确定", command=dialog.destroy)
        confirm_button.pack(pady=10)
        dialog.grab_set()    # 捕获焦点，确保当前窗口操作完成
        dialog.wait_window() # 等待当前窗口关闭后继续

        # 获取文本框内容，逐行处理
        content = text_widget.get("1.0", tk.END).strip()
        lines = content.splitlines()
        chapter = []
        first_verse = True
        verse_num = 1
        for line in lines:
            if not line.strip():
                continue
            if first_verse:
                # 第一行自动作为第一节，经文编号为1
                chapter.append({"verse": 1, "text": line})
                first_verse = False
            else:
                # 尝试判断行首是否为数字（表示节号）
                parts = line.split(' ', 1)
                try:
                    num = int(parts[0])
                    verse_num = num
                    verse_text = parts[1] if len(parts) > 1 else ""
                except ValueError:
                    # 如果行首不是数字，则沿用上一节的编号
                    verse_text = line
                chapter.append({"verse": verse_num, "text": verse_text})
        chapters.append(chapter)
    return chapters

def display_output(chapters):
    # 创建新窗口用于显示所有生成的内容
    output_window = tk.Toplevel(root)
    output_window.title("生成的经文内容")
    st = scrolledtext.ScrolledText(output_window, width=80, height=30, fg="green", font=("Menlo", 10))
    st.pack(fill="both", expand=True, padx=10, pady=10)
    output_text = ""
    for i, chapter in enumerate(chapters, start=1):
        output_text += f"chapters[{i}] = [\n"
        for verse in chapter:
            # 如果经文中包含双引号，则转义
            verse_text = verse['text'].replace('"', '\\"')
            output_text += f'  {{ verse: {verse["verse"]}, text: "{verse_text}" }},\n'
        output_text += "];\n\n"
    st.insert("1.0", output_text)
    st.configure(state="disabled")  # 禁止编辑

# 初始化主窗口并隐藏，因为我们只使用弹出窗口
root = tk.Tk()
root.withdraw()

chapters = input_chapters()
if chapters is not None:
    display_output(chapters)

root.mainloop()
