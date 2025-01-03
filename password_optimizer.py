#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

class PasswordOptimizer:
    def __init__(self):
        self.invalid_reasons = {
            'too_short': 0,
            'too_long': 0,
            'invalid_chars': 0,
            'whitespace': 0
        }
    
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
    
    def optimize_passwords(self, passwords):
        """优化密码列表"""
        # 重置统计
        self.invalid_reasons = {k: 0 for k in self.invalid_reasons}
        
        # 1. 去除重复
        unique_passwords = list(dict.fromkeys(passwords))
        
        # 2. 按长度排序
        unique_passwords.sort(key=len)
        
        # 3. 过滤无效密码
        valid_passwords = []
        for p in unique_passwords:
            if len(p) < 8:
                self.invalid_reasons['too_short'] += 1
            elif len(p) > 63:
                self.invalid_reasons['too_long'] += 1
            elif p.isspace():
                self.invalid_reasons['whitespace'] += 1
            elif not all(32 <= ord(c) <= 126 for c in p):
                self.invalid_reasons['invalid_chars'] += 1
            else:
                valid_passwords.append(p)
        
        return valid_passwords
    
    def optimize_password_file(self, input_file, output_file=None):
        """优化密码文件"""
        if output_file is None:
            output_file = input_file
            
        try:
            # 读取原始密码
            with open(input_file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            original_count = len(passwords)
            
            # 优化密码
            valid_passwords = self.optimize_passwords(passwords)
            
            # 保存优化后的密码
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(valid_passwords))
            
            return {
                'original_count': original_count,
                'optimized_count': len(valid_passwords),
                'invalid_reasons': self.invalid_reasons
            }
            
        except Exception as e:
            print(f"[-] 优化密码文件失败: {str(e)}")
            sys.exit(1)

def main():
    """命令行工具"""
    import argparse
    parser = argparse.ArgumentParser(description='WiFi密码字典优化工具')
    parser.add_argument('input_file', help='输入密码文件')
    parser.add_argument('-o', '--output', help='输出文件 (默认覆盖输入文件)')
    
    args = parser.parse_args()
    
    optimizer = PasswordOptimizer()
    result = optimizer.optimize_password_file(args.input_file, args.output)
    
    print(f"\n密码优化结果:")
    print(f"原始密码数量: {result['original_count']}")
    print(f"优化后数量: {result['optimized_count']}")
    print(f"\n无效密码统计:")
    print(f"- 密码太短 (<8): {result['invalid_reasons']['too_short']}")
    print(f"- 密码太长 (>63): {result['invalid_reasons']['too_long']}")
    print(f"- 包含无效字符: {result['invalid_reasons']['invalid_chars']}")
    print(f"- 纯空格密码: {result['invalid_reasons']['whitespace']}")

if __name__ == "__main__":
    main() 