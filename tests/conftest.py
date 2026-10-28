"""离线测试公共配置：确保项目根目录可 import（config/database 等为顶层模块）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
