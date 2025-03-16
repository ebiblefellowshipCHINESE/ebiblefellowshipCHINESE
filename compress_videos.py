import os
import subprocess
import logging
from pathlib import Path

# 配置日志
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('video_compress.log'), logging.StreamHandler()])

# 配置参数
DOCUMENTS_DIR = Path("/Users/owner/Documents")
TARGET_SIZE_MB = 20
ALLOWED_EXTENSIONS = {'.mp4', '.mov', '.avi', '.mkv', '.webm'}
COMPRESSED_BITRATE = "400k"  # 视频比特率
AUDIO_BITRATE = "64k"     # 音频比特率
RESOLUTION = "640:480"    # 输出分辨率
PRESET = "slow"           # x264编码预设


def compress_video(input_path: Path):
    """使用ffmpeg压缩视频文件"""
    output_path = input_path.with_stem(f"{input_path.stem}_compressed")
    
    try:
        cmd = [
            "ffmpeg", "-i", str(input_path),
            "-c:v", "libx264", "-preset", PRESET,
            "-b:v", COMPRESSED_BITRATE, "-maxrate", COMPRESSED_BITRATE,
            "-bufsize", "800k", "-vf", f"scale={RESOLUTION}",
            "-c:a", "aac", "-b:a", AUDIO_BITRATE,
            "-y", str(output_path)
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        # 检查压缩后文件大小
        compressed_size = output_path.stat().st_size / (1024 * 1024)
        if compressed_size > TARGET_SIZE_MB:
            logging.warning(f"二次压缩 {output_path}: 当前大小 {compressed_size:.1f}MB")
            # 调整参数再次压缩
            newer_path = output_path.with_stem(f"{output_path.stem}_2x")
            cmd.insert(cmd.index(COMPRESSED_BITRATE), "-b:v")
            cmd[cmd.index(COMPRESSED_BITRATE)] = "300k"
            cmd[cmd.index("-bufsize")+1] = "600k"
            subprocess.run(cmd, check=True)
            output_path = newer_path
        
        logging.info(f"成功压缩: {input_path} -> {output_path} ({compressed_size:.1f}MB)")
        return output_path
    
    except subprocess.CalledProcessError as e:
        logging.error(f"压缩失败: {input_path}\n错误信息: {e.stderr.decode()}")
        if output_path.exists():
            output_path.unlink()
        return None


def process_directory():
    """处理目录中的所有视频文件"""
    for root, _, files in os.walk(DOCUMENTS_DIR):
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in ALLOWED_EXTENSIONS:
                logging.info(f"开始处理: {file_path}")
                result = compress_video(file_path)
                if result:
                    # 删除原文件（谨慎操作）
                    # file_path.unlink()
                    # logging.info(f"已删除原文件: {file_path}")
                    pass

if __name__ == "__main__":
    logging.info("=== 开始视频压缩任务 ===")
    process_directory()
    logging.info("=== 压缩任务完成 ===")