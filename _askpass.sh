#!/bin/bash
# 提供 BMC 的 SSH 密碼給 ssh client(配合 SSH_ASKPASS 使用)
echo "${BMC_PASS:-0penBmc}"
