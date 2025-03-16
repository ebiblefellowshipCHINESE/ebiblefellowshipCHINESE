import subprocess
import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DEST_DIR = Path("/Users/owner/Desktop/ebiblefellowshipCHINESE/public/static/files/")
REPO_ROOT = DEST_DIR.parent.parent

class GitHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = time.time()
        self.cooldown = 60  # 冷却时间60秒

    def on_modified(self, event):
        if time.time() - self.last_modified > self.cooldown:
            self.last_modified = time.time()
            try:
                subprocess.run(['git', '-C', str(REPO_ROOT), 'add', '.'], check=True)
                commit_msg = f'自动同步: {time.strftime("%Y-%m-%d %H:%M:%S")}'
                subprocess.run(['git', '-C', str(REPO_ROOT), 'commit', '-m', commit_msg], check=True)
                
                # 带重试机制的推送
                for attempt in range(3):
                    try:
                        subprocess.run(['git', '-C', str(REPO_ROOT), 'push'], check=True)
                        logging.info('✅ 成功推送Git变更')
                        break
                    except Exception as e:
                        if attempt == 2:
                            raise
                        logging.warning(f'推送失败，第{attempt+1}次重试...')
                        time.sleep(10)
            
            except subprocess.CalledProcessError as e:
                logging.error(f'Git操作失败: {e.output.decode()}')
            except Exception as e:
                logging.error(f'意外错误: {str(e)}')

def start_git_watcher():
    event_handler = GitHandler()
    observer = Observer()
    observer.schedule(event_handler, path=str(DEST_DIR), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    start_git_watcher()