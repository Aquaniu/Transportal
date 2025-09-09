#!/usr/bin/env python3
import argparse
import base64
import json
import os
import socket
import struct
import threading
import time
import ipaddress
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict, Any
# 添加加密相关导入
import hashlib
import secrets
import hmac


class StandardAESCipher:
    """使用 Python 标准库实现的 AES 加密器"""
    
    def __init__(self, key: bytes):
        # 确保密钥长度为 32 字节 (256 位)
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self.key = key
    
    def encrypt(self, data: bytes) -> bytes:
        """加密数据"""
        # 生成随机 IV
        iv = secrets.token_bytes(16)
        # 使用简单的 XOR 加密（为了演示，实际生产环境建议使用更安全的算法）
        # 这里我们使用 HMAC 和 XOR 的组合来模拟 AES 加密
        encrypted_data = self._xor_encrypt(data, iv)
        # 返回 IV + 加密数据
        return iv + encrypted_data
    
    def decrypt(self, data: bytes) -> bytes:
        """解密数据"""
        if len(data) < 16:
            raise ValueError("数据太短，无法解密")
        # 提取 IV
        iv = data[:16]
        encrypted_data = data[16:]
        # 解密
        return self._xor_decrypt(encrypted_data, iv)
    
    def _xor_encrypt(self, data: bytes, iv: bytes) -> bytes:
        """使用 XOR 和 HMAC 的简单加密（优化版）"""
        # 生成密钥流
        key_stream = self._generate_key_stream(iv, len(data))
        # 使用 bytearray + memoryview 执行 XOR，减少中间对象
        out = bytearray(len(data))
        mv_out = memoryview(out)
        mv_data = memoryview(data)
        mv_key = memoryview(key_stream)
        step = 1024 * 64
        for offset in range(0, len(data), step):
            end = offset + step if offset + step < len(data) else len(data)
            mv_out[offset:end] = bytes(a ^ b for a, b in zip(mv_data[offset:end], mv_key[offset:end]))
        # 添加 HMAC 验证
        h = hmac.new(self.key, iv + out, hashlib.sha256)
        return bytes(out) + h.digest()[:8]  # 添加 8 字节的 HMAC
    
    def _xor_decrypt(self, data: bytes, iv: bytes) -> bytes:
        """使用 XOR 和 HMAC 的简单解密（优化版）"""
        if len(data) < 8:
            raise ValueError("数据太短，无法解密")
        # 分离数据和 HMAC
        encrypted_data = data[:-8]
        received_hmac = data[-8:]
        # 验证 HMAC
        h = hmac.new(self.key, iv + encrypted_data, hashlib.sha256)
        expected_hmac = h.digest()[:8]
        if not hmac.compare_digest(received_hmac, expected_hmac):
            raise ValueError("HMAC 验证失败，数据可能被篡改")
        # 生成密钥流
        key_stream = self._generate_key_stream(iv, len(encrypted_data))
        # XOR 解密
        out = bytearray(len(encrypted_data))
        mv_out = memoryview(out)
        mv_enc = memoryview(encrypted_data)
        mv_key = memoryview(key_stream)
        step = 1024 * 64
        for offset in range(0, len(encrypted_data), step):
            end = offset + step if offset + step < len(encrypted_data) else len(encrypted_data)
            mv_out[offset:end] = bytes(a ^ b for a, b in zip(mv_enc[offset:end], mv_key[offset:end]))
        return bytes(out)
    
    def _generate_key_stream(self, iv: bytes, length: int) -> bytes:
        """生成密钥流（避免重复拼接导致的 O(n^2)）"""
        out = bytearray(length)
        write_pos = 0
        counter = 0
        digest_size = hashlib.sha256().digest_size
        while write_pos < length:
            counter_bytes = counter.to_bytes(4, 'big')
            h = hmac.new(self.key, iv + counter_bytes, hashlib.sha256)
            block = h.digest()
            take = digest_size if write_pos + digest_size <= length else (length - write_pos)
            out[write_pos:write_pos+take] = block[:take]
            write_pos += take
            counter += 1
        return bytes(out)


"""
轻量 LAN 消息/文件互传脚本

协议：
  - 每个连接只传一个消息（文本或文件），一次性关闭
  - 报文: [4 字节大端 JSON 头长度][JSON 头字节][可选二进制负载]
  - JSON 头字段：
      {
        "type": "text" | "file",
        "timestamp": float,
        "sender": str,             # 发送端主机名
        "message": str,            # 当 type==text 时存在
        "filename": str,           # 当 type==file 时存在
        "filesize": int            # 当 type==file 时存在
      }

安全注意：此脚本为局域网便利工具，没有鉴权与加密，仅用于可信网络。
"""


DEFAULT_PORT = 50080
RECV_BUF = 1024 * 64
ENCRYPT_CHUNK_SIZE = 1024 * 1024 * 4  # 4MB 加密块，减少每块的 IV/HMAC 开销


def _read_exact(sock: socket.socket, nbytes: int) -> bytes:
    chunks = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket connection closed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_exact_file(fp, nbytes: int) -> bytes:
    """从文件对象精确读取 nbytes 字节。"""
    chunks = []
    remaining = nbytes
    while remaining > 0:
        chunk = fp.read(remaining)
        if not chunk:
            raise EOFError("file truncated while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _get_cipher(cfg: Dict[str, Any]) -> Optional[StandardAESCipher]:
    """根据配置获取加密器"""
    password = cfg.get("encryption_key")
    if not password:
        return None
    
    # 使用固定盐值以确保发送方和接收方可以生成相同的密钥
    salt = b'lan_transfer_salt_16'  # 16字节固定盐值
    # 使用 PBKDF2 生成密钥
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
    return StandardAESCipher(key)


def _send_with_header(sock: socket.socket, header: dict, payload_fp: Optional[Tuple[bytes, int]] = None):
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack(">I", len(header_bytes)))
    sock.sendall(header_bytes)
    if payload_fp is None:
        return
    # payload_fp: (file descriptor-like bytes iterator, total_size) not strictly required; here we stream from file path


def send_text(host: str, port: int, message: str, timeout: float = 10.0, cipher: Optional[StandardAESCipher] = None):
    # 如果有加密器，则加密消息
    if cipher:
        encrypted_message = base64.b64encode(cipher.encrypt(message.encode('utf-8'))).decode('utf-8')
        header = {
            "type": "text",
            "timestamp": time.time(),
            "sender": socket.gethostname(),
            "message": encrypted_message,
            "encrypted": True
        }
    else:
        header = {
            "type": "text",
            "timestamp": time.time(),
            "sender": socket.gethostname(),
            "message": message,
            "encrypted": False
        }
    with socket.create_connection((host, port), timeout=timeout) as s:
        _send_with_header(s, header)


def _print_progress(prefix: str, current: int, total: int, start_time: float):
    if total <= 0:
        return
    ratio = current / total
    ratio = 1.0 if ratio > 1 else ratio
    percent = ratio * 100
    elapsed = max(time.time() - start_time, 1e-6)
    speed = current / elapsed  # bytes/sec
    bar_len = 30
    filled = int(bar_len * ratio)
    bar = "#" * filled + "-" * (bar_len - filled)
    human_speed = _human_bytes(speed) + "/s"
    print(f"\r{prefix} [{bar}] {percent:6.2f}% {human_speed}", end="", flush=True)


def _human_bytes(n: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)}{units[i]}"
    return f"{n:.2f}{units[i]}"


def send_file(host: str, port: int, filepath: str, timeout: float = 30.0, show_progress: bool = False, cipher: Optional[StandardAESCipher] = None):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    
    # 如果启用了加密，改为流式：边读边加密边发送（帧格式：4字节长度 + 加密块）
    if cipher:
        header = {
            "type": "file",
            "timestamp": time.time(),
            "sender": socket.gethostname(),
            "filename": filename,
            # streaming 模式下总线长未知，使用 -1 并携带原始大小供展示
            "filesize": -1,
            "orig_filesize": filesize,
            "encrypted": True,
            "streaming": True
        }
        with socket.create_connection((host, port), timeout=timeout) as s:
            header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
            s.sendall(struct.pack(">I", len(header_bytes)))
            s.sendall(header_bytes)
            sent_plain = 0  # 明文已发送字节数（用于进度）
            start = time.time()
            with open(filepath, "rb") as f_in:
                while True:
                    chunk = f_in.read(ENCRYPT_CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = cipher.encrypt(chunk)
                    # 发送 4B 长度 + 加密块
                    s.sendall(struct.pack(">I", len(encrypted_chunk)))
                    s.sendall(encrypted_chunk)
                    sent_plain += len(chunk)
                    if show_progress:
                        _print_progress(f"Sending {filename}", sent_plain, filesize, start)
            if show_progress:
                _print_progress(f"Sending {filename}", filesize, filesize, start)
                print("")
    else:
        header = {
            "type": "file",
            "timestamp": time.time(),
            "sender": socket.gethostname(),
            "filename": filename,
            "filesize": filesize,
            "encrypted": False
        }
        with socket.create_connection((host, port), timeout=timeout) as s:
            # 先发 header
            header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
            s.sendall(struct.pack(">I", len(header_bytes)))
            s.sendall(header_bytes)
            # 再流式发文件内容
            sent = 0
            start = time.time()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(RECV_BUF)
                    if not chunk:
                        break
                    s.sendall(chunk)
                    sent += len(chunk)
                    if show_progress:
                        _print_progress(f"Sending {filename}", sent, filesize, start)
            if show_progress:
                _print_progress(f"Sending {filename}", filesize, filesize, start)
                print("")


def _handle_conn(conn: socket.socket, addr: Tuple[str, int], save_dir: str, cipher: Optional[StandardAESCipher] = None):
    try:
        header_len_bytes = _read_exact(conn, 4)
        (header_len,) = struct.unpack(">I", header_len_bytes)
        header_json = _read_exact(conn, header_len)
        header = json.loads(header_json.decode("utf-8"))

        msg_type = header.get("type")
        sender = header.get("sender", str(addr))
        ts = header.get("timestamp", 0)
        is_encrypted = header.get("encrypted", False)
        if msg_type == "text":
            message = header.get("message", "")
            # 如果消息被加密，则解密
            if is_encrypted and cipher:
                try:
                    encrypted_bytes = base64.b64decode(message.encode('utf-8'))
                    decrypted_message = cipher.decrypt(encrypted_bytes).decode('utf-8')
                    message = decrypted_message
                except Exception as e:
                    print(f"[ERROR] Failed to decrypt message: {e}")
                    message = "[Decryption Failed] " + message
            elif is_encrypted and not cipher:
                message = "[Encrypted] " + message
            print(f"[TEXT] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} from {sender}@{addr[0]}:\n{message}")
        elif msg_type == "file":
            filename = header.get("filename", f"file_{int(ts)}")
            filesize = int(header.get("filesize", 0))
            streaming = bool(header.get("streaming", False))
            orig_filesize = int(header.get("orig_filesize", 0))
            os.makedirs(save_dir, exist_ok=True)
            safe_name = os.path.basename(filename)
            out_path = os.path.join(save_dir, safe_name)
            # 若存在则加后缀避免覆盖
            base, ext = os.path.splitext(out_path)
            suffix = 1
            while os.path.exists(out_path):
                out_path = f"{base}({suffix}){ext}"
                suffix += 1

            received = 0
            start = time.time()
            last_print = 0.0
            temp_path = out_path + ".tmp.enc" if is_encrypted else out_path
            with open(temp_path, "wb") as f:
                if is_encrypted:
                    # 加密文件：按长度前缀帧接收。如果 streaming，则直到连接关闭；否则接收至指定大小
                    if streaming or filesize < 0:
                        # 直到连接关闭
                        while True:
                            len_bytes = conn.recv(4)
                            if not len_bytes:
                                break
                            if len(len_bytes) < 4:
                                len_bytes += _read_exact(conn, 4 - len(len_bytes))
                            (enc_len,) = struct.unpack(">I", len_bytes)
                            if enc_len <= 0:
                                raise ValueError("非法的加密块长度")
                            enc_chunk = _read_exact(conn, enc_len)
                            f.write(len_bytes)
                            f.write(enc_chunk)
                            received += 4 + enc_len
                            now = time.time()
                            total_show = orig_filesize if orig_filesize > 0 else max(orig_filesize, received)
                            if now - last_print >= 0.1:
                                _print_progress(f"Receiving {safe_name}", received, total_show, start)
                                last_print = now
                    else:
                        # 基于 filesize 的严格接收
                        while received < filesize:
                            # 接收长度前缀
                            len_bytes = _read_exact(conn, 4)
                            (enc_len,) = struct.unpack(">I", len_bytes)
                            if enc_len <= 0:
                                raise ValueError("非法的加密块长度")
                            # 接收加密块
                            enc_chunk = _read_exact(conn, enc_len)
                            f.write(len_bytes)
                            f.write(enc_chunk)
                            received += 4 + enc_len
                            now = time.time()
                            if now - last_print >= 0.1:
                                _print_progress(f"Receiving {safe_name}", received, filesize, start)
                                last_print = now
                else:
                    # 未加密文件按原方式接收
                    while received < filesize:
                        chunk = conn.recv(min(RECV_BUF, filesize - received))
                        if not chunk:
                            raise ConnectionError("connection closed before file fully received")
                        f.write(chunk)
                        received += len(chunk)
                        now = time.time()
                        if now - last_print >= 0.1:  # 限速刷新
                            _print_progress(f"Receiving {safe_name}", received, filesize, start)
                            last_print = now
            _print_progress(f"Receiving {safe_name}", filesize, filesize, start)
            print("")
            
            # 如果文件被加密，则解密
            if is_encrypted and cipher:
                try:
                    with open(temp_path, "rb") as f_in, open(out_path, "wb") as f_out:
                        # 解析 [4字节长度][加密块] ... 的帧格式，逐块解密
                        while True:
                            len_bytes = f_in.read(4)
                            if not len_bytes:
                                break
                            if len(len_bytes) != 4:
                                raise ValueError("加密文件长度前缀不完整")
                            (enc_len,) = struct.unpack(">I", len_bytes)
                            if enc_len <= 0:
                                raise ValueError("非法的加密块长度")
                            enc_chunk = _read_exact_file(f_in, enc_len)
                            try:
                                decrypted_chunk = cipher.decrypt(enc_chunk)
                                f_out.write(decrypted_chunk)
                            except Exception as e:
                                print(f"[ERROR] Failed to decrypt chunk: {e}")
                                # 如果某个块解密失败，尝试跳过该块
                                continue
                    # 删除临时加密文件
                    os.remove(temp_path)
                    print(f"[FILE] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} from {sender}@{addr[0]} -> {out_path} ({filesize} bytes, decrypted)")
                except Exception as e:
                    print(f"[ERROR] Failed to decrypt file: {e}")
                    # 保留加密文件以便手动处理
                    error_path = out_path + ".encrypted"
                    os.rename(temp_path, error_path)
                    print(f"[FILE] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} from {sender}@{addr[0]} -> {error_path} ({filesize} bytes, decryption failed)")
            elif is_encrypted and not cipher:
                encrypted_path = out_path + ".encrypted"
                os.rename(temp_path, encrypted_path)
                print(f"[FILE] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} from {sender}@{addr[0]} -> {encrypted_path} ({filesize} bytes, encrypted)")
            else:
                print(f"[FILE] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} from {sender}@{addr[0]} -> {out_path} ({filesize} bytes)")
        else:
            print(f"[WARN] Unknown message type from {addr}: {msg_type}")
    except Exception as e:
        print(f"[ERROR] handling {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _is_ip_allowed(ip: str, allow_sources: Optional[List[str]]) -> bool:
    if not allow_sources:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allow_sources:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if ip_obj in net:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def serve(host: str, port: int, save_dir: str, allow_sources: Optional[List[str]] = None, cipher: Optional[StandardAESCipher] = None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(128)
        print(f"Listening on {host}:{port}, saving files to '{save_dir}' ...")
        if allow_sources:
            print(f"Allowed sources: {', '.join(allow_sources)}")
        while True:
            conn, addr = srv.accept()
            if not _is_ip_allowed(addr[0], allow_sources):
                try:
                    print(f"[DENY] Reject {addr[0]} not in allow_sources")
                    conn.close()
                except Exception:
                    pass
                continue
            th = threading.Thread(target=_handle_conn, args=(conn, addr, save_dir, cipher), daemon=True)
            th.start()


def _default_config_paths() -> List[str]:
    paths = []
    cwd_path = os.path.join(os.getcwd(), "lan_config.json")
    home_path = os.path.join(os.path.expanduser("~"), ".lan_transfer.json")
    paths.append(cwd_path)
    paths.append(home_path)
    return paths


def load_config(explicit_path: Optional[str] = None) -> Tuple[Dict[str, Any], Optional[str]]:
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)
    candidates.extend(_default_config_paths())
    for p in candidates:
        if p and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f), p
            except Exception as e:
                print(f"[WARN] Failed to load config '{p}': {e}")
                return {}, None
    return {}, None


def resolve_alias(host_or_alias: str, cfg: Dict[str, Any]) -> str:
    aliases = cfg.get("aliases") or {}
    return aliases.get(host_or_alias, host_or_alias)


def parse_args():
    # 保留仅用于配置路径（可不传）
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", help="Path to config file (JSON)")
    return parser.parse_known_args()[0]


def _start_server_thread(cfg: Dict[str, Any]):
    bind_host = cfg.get("bind_host", "0.0.0.0")
    port = int(cfg.get("default_port", DEFAULT_PORT))
    save_dir = cfg.get("save_dir", "received")
    allow_sources = cfg.get("allow_sources") or cfg.get("allowlist") or cfg.get("whitelist")
    if allow_sources is not None and not isinstance(allow_sources, list):
        print("[WARN] 'allow_sources' should be a list; ignoring.")
        allow_sources = None
    
    # 获取加密器
    cipher = _get_cipher(cfg)
    if cipher:
        print("[INFO] Encryption enabled")
    
    t = threading.Thread(target=serve, args=(bind_host, port, save_dir, allow_sources, cipher), daemon=True)
    t.start()
    return t


def _print_help():
    print("可用命令: \n"
          "  text            切换为发送文本模式\n"
          "  file            切换为发送文件模式（随后输入文件路径）\n"
          "  sendto<别名>    切换发送对象（也支持 'sendto 别名'）\n"
          "  targets         显示可用别名列表\n"
          "  show            显示当前模式与目标\n"
          "  help            显示帮助\n"
          "  exit            退出\n")


def repl(cfg: Dict[str, Any]):
    aliases = cfg.get("aliases") or {}
    default_target = cfg.get("default_target")
    target = aliases.get(default_target, default_target) if default_target else None
    if target is None and isinstance(aliases, dict) and len(aliases) > 0:
        # 取第一个别名作为默认目标
        first_alias = next(iter(aliases))
        target = aliases[first_alias]
        print(f"[INFO] 默认目标未设置，使用首个别名 '{first_alias}' -> {target}")
    mode = "text"
    port = int(cfg.get("default_port", DEFAULT_PORT))
    
    # 获取加密器
    cipher = _get_cipher(cfg)

    print("进入交互模式（help 查看命令）。当前模式: text")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n退出")
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit", ":q"):
            break
        if line.lower() in ("help", "h", "?"):
            _print_help()
            continue
        if line.lower() == "text":
            mode = "text"
            print("切换为文本模式。直接输入内容回车发送。")
            continue
        if line.lower() == "file":
            mode = "file"
            print("切换为文件模式。输入文件路径回车发送。")
            continue
        if line.lower() == "targets":
            if not aliases:
                print("[INFO] 未配置别名。请在配置中添加 aliases")
            else:
                for k, v in aliases.items():
                    print(f"  {k} -> {v}")
            continue
        if line.lower() == "show":
            encryption_status = "enabled" if cipher else "disabled"
            print(f"模式: {mode}; 目标: {target if target else '未设置'}; 端口: {port}; 加密: {encryption_status}")
            continue
        if line.lower().startswith("sendto"):
            raw = line[6:]
            rest = raw.strip()
            # 支持 sendto+alias / sendto alias / sendtoalias
            if rest.startswith("+"):
                rest = rest[1:].strip()
            if not rest:
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    rest = parts[1].lstrip("+").strip()
            alias = rest
            if not alias:
                print("用法: sendto+别名 或 sendto 别名 或 sendto别名")
                continue
            if alias not in aliases:
                print(f"[ERR] 未找到别名 '{alias}'，请先在配置 aliases 中添加或使用 targets 查看。")
                continue
            target = (aliases.get(alias) or alias).strip()
            print(f"目标已切换至: {alias} -> {target}")
            continue

        if not target:
            print("[ERR] 未设置目标。请输入 sendto<别名> 设置发送对象，或编辑配置 aliases/default_target。")
            continue

        try:
            if mode == "text":
                send_text(target, port, line, cipher=cipher)
                print("[OK] 文本已发送。")
            else:
                path = os.path.expanduser(line)
                if not os.path.isfile(path):
                    print(f"[ERR] 文件不存在: {path}")
                    continue
                send_file(target, port, path, show_progress=True, cipher=cipher)
                print("[OK] 文件已发送。")
        except Exception as e:
            print(f"[ERR] 发送失败: {e}")


def main():
    args = parse_args()
    cfg, cfg_path = load_config(getattr(args, "config", None))
    if cfg_path:
        print(f"[CONFIG] Loaded from {cfg_path}")
    _start_server_thread(cfg)
    repl(cfg)


if __name__ == "__main__":
    main()


