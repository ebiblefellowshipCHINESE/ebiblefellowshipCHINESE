import os
import shutil
import datetime
import hashlib
import json
import time
from pathlib import Path
import threading

# 存储哈希值的文件（放在目标目录下）
HASH_RECORD_FILE = "file_hashes.json"

def calculate_sha256(file_path):
    """计算文件的SHA256哈希值"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        print(f"无法读取文件 {file_path}，可能正在同步")
        return None

def load_hash_records(target_dir):
    """加载已保存的哈希值记录"""
    hash_file = os.path.join(target_dir, HASH_RECORD_FILE)
    if os.path.exists(hash_file):
        with open(hash_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_hash_records(hash_dict, target_dir):
    """保存哈希值记录"""
    hash_file = os.path.join(target_dir, HASH_RECORD_FILE)
    with open(hash_file, 'w', encoding='utf-8') as f:
        json.dump(hash_dict, f, indent=4)

def clear_sha256_records(target_dir):
    """一键清除SHA256记录（案件）"""
    hash_file = os.path.join(target_dir, HASH_RECORD_FILE)
    if os.path.exists(hash_file):
        os.remove(hash_file)
        print(f"已清除SHA256记录（案件）: {hash_file}")
    else:
        print("暂无SHA256记录（案件）可清除")
    
    html_file = os.path.join(target_dir, "Bibleflie.html")
    if os.path.exists(html_file):
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                content = f.read()
            auto_pos = content.find('//auto')
            if auto_pos != -1:
                new_content = content[auto_pos:]
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"已重置 {html_file} 中的文件信息")
        except Exception as e:
            print(f"重置 {html_file} 失败: {str(e)}")

def get_file_info(file_path):
    """获取文件信息"""
    try:
        stat = os.stat(file_path)
        size = stat.st_size
        upload_time = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d')
        return size, upload_time
    except (IOError, OSError):
        return None, None

def get_file_type_and_icon(ext):
    """根据文件扩展名返回类型和图标"""
    ext = ext.lower()
    if ext in ['.jpg', '.jpeg', '.png', '.gif']:
        return "jpg", "fas fa-image"
    elif ext in ['.txt']:
        return "txt", "fas fa-file-alt"
    elif ext in ['.mp4', '.mov', '.avi']:
        return "video", "fas fa-video"
    elif ext in ['.doc', '.docx']:
        return "word", "fas fa-file-word"
    elif ext == '.pdf':
        return "pdf", "fas fa-file-pdf"
    else:
        return "file", "fas fa-file"

def modify_bibleflie_html(target_dir, file_info_list):
    """在Bibleflie.html的//auto上方添加文件信息"""
    html_file = os.path.join(target_dir, "Bibleflie.html")
    if not os.path.exists(html_file):
        print(f"未找到 {html_file}，跳过修改")
        return
    
    # 只生成一行，标签无引号，值有引号
    new_code = ""
    if file_info_list:  # 只取第一个文件信息
        info = file_info_list[0]
        new_code = f'{{ type: "{info["type"]}", icon: "{info["icon"]}", ext: "{info["ext"]}", name: "{info["name"]}", size: "{info["size"]}", date: "{info["date"]}", url: "{info["url"]}" }}'
    new_code = f"\n{new_code},"
    
    try:
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        auto_pos = content.find('//auto')
        if auto_pos == -1:
            print(f"{html_file} 中未找到 //auto，添加至文件顶部")
            content = new_code + content
        else:
            content = content[:auto_pos] + new_code + content[auto_pos:]
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"已更新 {html_file}")
    except Exception as e:
        print(f"修改 {html_file} 失败: {str(e)}")

def scan_and_process_directory(source_dir, target_dir, subfolder="ebfflie"):
    """扫描目录并处理文件"""
    target_subfolder = os.path.join(target_dir, subfolder)
    os.makedirs(target_subfolder, exist_ok=True)
    hash_records = load_hash_records(target_dir)
    updated = False
    file_info_list = []
    
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.startswith('.'):
                continue
            
            source_path = os.path.join(root, file)
            relative_path = os.path.relpath(source_path, source_dir)
            target_path = os.path.join(target_subfolder, relative_path)
            
            current_hash = calculate_sha256(source_path)
            if current_hash is None:
                continue
            
            if relative_path in hash_records and hash_records[relative_path] == current_hash:
                continue
            
            size, upload_time = get_file_info(source_path)
            if size is None:
                continue
            
            ext = os.path.splitext(file)[1].lower()
            file_name = file
            size_mb = f"{size / (1024 * 1024):.1f} MB"
            type_val, icon_val = get_file_type_and_icon(ext)
            url = f"#{len(file_name) % 10}"  # 模仿 #3
            
            file_info = {
                "type": type_val,
                "icon": icon_val,
                "ext": ext,
                "name": file_name,
                "size": size_mb,
                "date": upload_time,
                "url": url
            }
            
            print(f"检测到新文件或更改: {relative_path}")
            print(f"大小: {size_mb}")
            print(f"上传时间: {upload_time}")
            print(f"SHA256: {current_hash}")
            print("-" * 50)
            
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            shutil.copy2(source_path, target_path)
            
            hash_records[relative_path] = current_hash
            file_info_list.append(file_info)
            updated = True
            break  # 只处理一个文件
            
    if updated:
        save_hash_records(hash_records, target_dir)
        modify_bibleflie_html(target_dir, file_info_list)
        return True
    return False

def user_input_handler(target_dir, stop_event):
    """处理用户输入"""
    while not stop_event.is_set():
        try:
            command = input().strip().lower()
            if command == "clear":
                clear_sha256_records(target_dir)
            elif command == "exit":
                print("正在停止监控...")
                stop_event.set()
        except EOFError:
            pass
        except Exception as e:
            print(f"输入处理错误: {str(e)}")

def monitor_directory(source_dir, target_dir, scan_interval=60):
    """无限监控目录变化并支持一键清除案件"""
    print(f"开始监控目录: {source_dir}")
    print(f"目标目录: {target_dir}/ebfflie")
    print(f"扫描间隔: {scan_interval}秒")
    print("输入 'clear' 清除案件（SHA256记录），输入 'exit' 停止监控")
    print("=" * 50)
    
    stop_event = threading.Event()
    input_thread = threading.Thread(target=user_input_handler, args=(target_dir, stop_event))
    input_thread.daemon = True
    input_thread.start()
    
    while not stop_event.is_set():
        try:
            has_changes = scan_and_process_directory(source_dir, target_dir)
            if has_changes:
                print("\n文件已更新，等待下次扫描...")
            else:
                print(f"[{datetime.datetime.now()}] 无变化，等待下次扫描...")
            
            time.sleep(scan_interval)
            
        except Exception as e:
            print(f"发生错误: {str(e)}")
            time.sleep(scan_interval)
    
    print("\n监控已停止")

def main():
    source_directory = "/Users/owner/EBF Dropbox/2. 中文 Chinese (Mandarin, Cantonese, Wu)/EBFflie/"
    target_directory = "/Users/Owner/Desktop/Chineseebiblefellowship/"
    monitor_directory(source_directory, target_directory, scan_interval=0.1)

if __name__ == "__main__":
    main()