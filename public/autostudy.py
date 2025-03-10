import os
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox
from docx import Document

def docx_to_html(docx_path, output_html, font_size, theme):
    doc = Document(docx_path)

    # Determine the CSS for Day and Night mode
    if theme == 'Night':
        background_color = '#121212'
        text_color = '#FFFFFF'
        link_color = '#BB86FC'
    else:
        background_color = '#CCE8CF'
        text_color = '#000000'
        link_color = '#007BFF'

    html = [
        "<!DOCTYPE html>",
        "<html lang='zh'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>文档转换</title>",
        "<style>",
        f"body {{ background-color: {background_color}; font-family: Arial, sans-serif; padding-top: 120px; margin: 0; color: {text_color}; }}",
        ".header { position: fixed; top: 0; left: 0; width: 100%; background-color: white; border-radius: 15px; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); z-index: 999; }",
        ".header .return { background-color: #0083F; border-radius: 25px; padding: 10px 15px; color: white; text-decoration: none; font-size: 14px; transition: background-color 0.3s ease; }",
        ".header .return:hover { background-color: #0062BE; }",
        ".header .title { font-size: 24px; font-weight: bold; margin: 0; }",
        ".header .slider-container { display: flex; align-items: center; }",
        ".header .slider-container .slider-label { font-size: 14px; margin-right: 10px; color: black; }",
        "#font-size-slider { width: 150px; }",
        f".title {{ font-size: {font_size}; font-weight: bold; margin: 40px 0; }}",
        f".toc {{ font-size: 50px; color: {link_color}; text-decoration: none; display: block; margin: 10px auto; font-weight: bold; text-align: center; transition: all 0.3s ease; }}",
        ".toc:hover { color: red; transform: scale(1.1); }",
        "h1, h2, h3 { font-size: 50.5px; font-weight: bold; margin: 50px 0; text-align: center; }",
        f"p {{ text-indent: 2em; font-size: {int(font_size) * 0.6}px; line-height: 1.8; margin: 20px; text-align: left; }}",
        "b { font-weight: bold; }",
        "a { text-decoration: none; color: inherit; }",  # Remove underlines from links
        ".slider-container { position: fixed; top: 10px; left: 10px; background-color: rgba(0, 0, 0, 0.5); padding: 10px; border-radius: 15px; z-index: 1000; }",
        ".slider-label { color: white; font-size: 18px; margin-right: 10px; }",
        "#font-size-slider { width: 200px; }",
        ".return-button { position: fixed; bottom: 20px; right: 20px; background-color: #007BFF; color: white; padding: 15px 25px; border-radius: 50%; font-size: 18px; transition: background-color 0.3s ease; z-index: 999; }",
        ".return-button:hover { background-color: #0062BE; }",
        "</style>",
        "</head>",
        "<body id='top'>",
        "<div class='header'>",
        "<a href='#top' class='return'>返回顶部</a>",
        "<div class='title'>目录</div>",
        "<div class='slider-container'>",
        "<span class='slider-label'>更改字体大小</span>",
        "<input type='range' id='font-size-slider' min='10' max='60' value='50' step='1' />",
        "</div></div>",
        "<div class='content'>"
    ]

    toc = []
    body = []
    header_count = 0

    for para in doc.paragraphs:
        txt = para.text.strip()
        if not txt:
            continue
        
        # Check if it's a heading
        if para.style.name.startswith("Heading"):
            header_count += 1
            header_id = f"title-{header_count}"
            toc.append(f"<a class='toc' href='#{header_id}'>{txt}</a>")
            body.append(f"<h1 id='{header_id}'>{txt}</h1>")
        else:
            # Process bold text
            formatted_text = ""
            for run in para.runs:
                if run.bold:
                    formatted_text += f"<b>{run.text}</b>"
                else:
                    formatted_text += run.text

            body.append(f"<p>{formatted_text}</p>")

    html.extend(toc)
    html.extend(body)
    html.append("</div>")

    # Add Return Button
    html.append("<button class='return-button' onclick='window.scrollTo({top: 0, behavior: \"smooth\"})'>返回顶部</button>")
    
    html.append("</body>")

    # Adding JavaScript for the font-size adjustment and smooth scrolling
    html.append("""
    <script>
        document.getElementById('font-size-slider').addEventListener('input', function() {
            var newSize = this.value + 'px';
            document.body.style.fontSize = newSize;
            document.querySelectorAll('h1, h2, h3, p').forEach(function(el) {
                el.style.fontSize = newSize;
            });
        });
    </script>
    """)

    html.append("</html>")

    with open(output_html, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

def select_file():
    path = filedialog.askopenfilename(filetypes=[("Word 文档", "*.docx")])
    if path:
        entry_var.set(path)

def convert_file():
    docx_path = entry_var.get()
    if not docx_path or not os.path.exists(docx_path):
        messagebox.showerror("错误", "请选择一个有效的 .docx 文件！")
        return

    font_size = font_size_var.get()
    theme = theme_var.get()

    output_html = os.path.splitext(docx_path)[0] + ".html"
    try:
        docx_to_html(docx_path, output_html, font_size, theme)
        messagebox.showinfo("转换成功", f"HTML 文件已生成：{output_html}")
        webbrowser.open("file://" + os.path.realpath(output_html))
    except Exception as e:
        messagebox.showerror("转换错误", "转换过程中出错：" + str(e))

root = tk.Tk()
root.title("Word 转 HTML")
root.geometry("600x400")
root.configure(bg="white")

# Labels and Entry
title_label = tk.Label(root, text="Word 转 HTML", font=("Arial", 18, "bold"), bg="white")
title_label.pack(pady=20)

entry_var = tk.StringVar()
file_entry = tk.Entry(root, textvariable=entry_var, width=50)
file_entry.pack(pady=10)

# Font Size Selector
font_size_var = tk.StringVar(value="24")
font_size_label = tk.Label(root, text="选择字体大小", bg="white", font=("Arial", 12))
font_size_label.pack(pady=5)
font_size_entry = tk.Entry(root, textvariable=font_size_var, width=5)
font_size_entry.pack(pady=5)

# Theme Selector (Day/Night mode)
theme_var = tk.StringVar(value="Day")
theme_label = tk.Label(root, text="选择模式 (Day / Night)", bg="white", font=("Arial", 12))
theme_label.pack(pady=5)
theme_option = tk.OptionMenu(root, theme_var, "Day", "Night")
theme_option.pack(pady=5)

# Buttons
select_button = tk.Button(root, text="选择文件", command=select_file, bg="#007BFF", fg="white", font=("Arial", 12), relief="solid", borderwidth=2)
select_button.pack(pady=5)

convert_button = tk.Button(root, text="转换为 HTML", command=convert_file, bg="#28A745", fg="white", font=("Arial", 12), relief="solid", borderwidth=2)
convert_button.pack(pady=20)

root.mainloop()