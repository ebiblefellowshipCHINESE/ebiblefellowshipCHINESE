import pyperclip
from googletrans import Translator
import time

# 初始化翻译器
translator = Translator()

# 存储上一次的剪贴板内容，避免重复翻译
last_text = ""

def translate_to_biblical_chinese(text):
    """将文本翻译成中文，尽量接近圣经风格"""
    try:
        # 使用 Google Translate 翻译成中文
        translated = translator.translate(text, src='es',dest='zh-cn').text
        
        # 手动调整部分翻译，接近圣经用语（示例调整）
        biblical_translations = {
            "God": "上帝",
            "Lord": "主",
           
        }
        
        result = translated
        for eng_word, biblical_word in biblical_translations.items():
            if eng_word.lower() in text.lower():
                result = result.replace(translated.split()[0], biblical_word)
        
        return result
    except Exception as e:
        print(f"Translation error: {e}")
        return text  # 如果出错，返回原文

def monitor_clipboard():
    global last_text
    while True:
        try:
            # 获取当前剪贴板内容
            current_text = pyperclip.paste()
            
            # 检查是否为新内容且不为空
            if current_text != last_text and current_text.strip():
                # 翻译成接近圣经风格的中文
                translated_text = translate_to_biblical_chinese(current_text)
                
                # 立即更新剪贴板
                pyperclip.copy(translated_text)
                
                # 验证剪贴板是否更新成功
                updated_text = pyperclip.paste()
                if updated_text == translated_text:
                    print(f"Original: {current_text}")
                    print(f"Translated: {translated_text}")
                    print("Clipboard updated successfully!")
                else:
                    print("Error: Clipboard update failed.")
                
                # 更新上一次文本
                last_text = current_text
                print("---")
            
            # 添加微小延迟，避免高频占用 CPU
            time.sleep(0.01)  # 0.1 秒足以快速响应，又不会卡顿
            
        except KeyboardInterrupt:
            print("Program stopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)  # 如果出错，暂停 1 秒后重试

def main():
    print("Translation tool started!")
    print("Copy any text to translate it to Biblical-style Chinese.")
    print("To exit, press Ctrl+C in terminal.")
    monitor_clipboard()

if __name__ == "__main__":
    main()