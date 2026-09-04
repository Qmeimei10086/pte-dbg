# pte-dbg
基于pte-hook的调试器保护工具

# 效果
![img2](https://github.com/Qmeimei10086/pte-dbg/blob/main/img/QQ20260905-005523.png?raw=true "img2")   
目前测试能够完全自由调试vmp任意版本,包括创建调试和附加调试
# 要求
目前只测试过20h1版本虚拟机，目前我的机子的虚拟机不能开虚拟化cpu因为会开启cr4.cet，导致无法开启内核强写，实体机没试过  
虚拟机推荐4-8核，内存4G以上，太少会有部分关键函数被换入分页文件，在hook时引发页面异常导致蓝屏  
# 使用
如果是创建调试，只需要在debugger栏里添加调试器的pid，由于pml4e的高位继承机制，创建线程会自动继承hook  
如果是附加调试，不仅需要将调试器加入debugger栏，还需要将被调试进程加入debuggee栏
运行时将编译好的pte-dbg.exe pte-dbg.sys 和 dbghelp.dll symsrv.dll 放一起，然后选择管理员身份启动
# 注意
请不要用来调试某游戏，pte hook是很早的hook技术，相较于ept/npt hook的无痕，你的hook在反作弊眼前几乎是裸奔  
本项目是为了处理本人的另一个项目: svm-dbg在面对创建调试需要hook及高频函数发生无法解决的卡顿而诞生的项目，创建调试的大部分用途仅仅是为了脱壳，本项目足矣，而且不需要不稳定的虚拟化  
# 参考
[1] https://github.com/Qmeimei10086/PTE_hook  
[2] https://github.com/Qmeimei10086/svm-dbg  
[3] https://github.com/xyddnljydd/vt-ReloadDbg    
