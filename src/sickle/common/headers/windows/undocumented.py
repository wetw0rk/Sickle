import ctypes

class _KTHREAD(ctypes.Structure):
    _fields_ = [
#struct _KTHREAD
#{
#    struct _DISPATCHER_HEADER Header;                                       //0x0
#    VOID* SListFaultAddress;                                                //0x18
#    ULONGLONG QuantumTarget;                                                //0x20
#    VOID* InitialStack;                                                     //0x28
#    VOID* volatile StackLimit;                                              //0x30
#    VOID* StackBase;                                                        //0x38
#    ULONGLONG ThreadLock;                                                   //0x40
#    volatile ULONGLONG CycleTime;                                           //0x48
#    ULONG CurrentRunTime;                                                   //0x50
#    ULONG ExpectedRunTime;                                                  //0x54
#    VOID* KernelStack;                                                      //0x58
#    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
#    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
#    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
#    volatile UCHAR Running;                                                 //0x71
#    UCHAR Alerted[2];                                                       //0x72
#    union
#    {
#        struct
#        {
#            ULONG AutoBoostActive:1;                                        //0x74
#            ULONG ReadyTransition:1;                                        //0x74
#            ULONG WaitNext:1;                                               //0x74
#            ULONG SystemAffinityActive:1;                                   //0x74
#            ULONG Alertable:1;                                              //0x74
#            ULONG Reserved1:1;                                              //0x74
#            ULONG ApcInterruptRequest:1;                                    //0x74
#            ULONG QuantumEndMigrate:1;                                      //0x74
#            ULONG SecureThread:1;                                           //0x74
#            ULONG TimerActive:1;                                            //0x74
#            ULONG SystemThread:1;                                           //0x74
#            ULONG ProcessDetachActive:1;                                    //0x74
#            ULONG Reserved2:1;                                              //0x74
#            ULONG ScbReadyQueue:1;                                          //0x74
#            ULONG ApcQueueable:1;                                           //0x74
#            ULONG Reserved3:1;                                              //0x74
#            ULONG WaitNextClearWobPriorityFloor:1;                          //0x74
#            ULONG TimerSuspended:1;                                         //0x74
#            ULONG SuspendedWaitMode:1;                                      //0x74
#            ULONG SuspendSchedulerApcWait:1;                                //0x74
#            ULONG CetUserShadowStack:1;                                     //0x74
#            ULONG BypassProcessFreeze:1;                                    //0x74
#            ULONG CetKernelShadowStack:1;                                   //0x74
#            ULONG StateSaveAreaDecoupled:1;                                 //0x74
#            ULONG Reserved:8;                                               //0x74
#        };
#        LONG MiscFlags;                                                     //0x74
#    };
#    union
#    {
#        struct
#        {
#            ULONG UserIdealProcessorFixed:1;                                //0x78
#            ULONG IsolationWidth:1;                                         //0x78
#            ULONG AutoAlignment:1;                                          //0x78
#            ULONG DisableBoost:1;                                           //0x78
#            ULONG AlertedByThreadId:1;                                      //0x78
#            ULONG QuantumDonation:1;                                        //0x78
#            ULONG EnableStackSwap:1;                                        //0x78
#            ULONG GuiThread:1;                                              //0x78
#            ULONG DisableQuantum:1;                                         //0x78
#            ULONG ChargeOnlySchedulingGroup:1;                              //0x78
#            ULONG DeferPreemption:1;                                        //0x78
#            ULONG QueueDeferPreemption:1;                                   //0x78
#            ULONG ForceDeferSchedule:1;                                     //0x78
#            ULONG SharedReadyQueueAffinity:1;                               //0x78
#            ULONG FreezeCount:1;                                            //0x78
#            ULONG TerminationApcRequest:1;                                  //0x78
#            ULONG AutoBoostEntriesExhausted:1;                              //0x78
#            ULONG KernelStackResident:1;                                    //0x78
#            ULONG TerminateRequestReason:2;                                 //0x78
#            ULONG ProcessStackCountDecremented:1;                           //0x78
#            ULONG RestrictedGuiThread:1;                                    //0x78
#            ULONG VpBackingThread:1;                                        //0x78
#            ULONG EtwStackTraceCrimsonApcDisabled:1;                        //0x78
#            ULONG EtwStackTraceApcInserted:8;                               //0x78
#        };
#        volatile LONG ThreadFlags;                                          //0x78
#    };
#    volatile UCHAR Tag;                                                     //0x7c
#    union
#    {
#        struct
#        {
#            UCHAR CalloutActive:1;                                          //0x7d
#            UCHAR ReservedStackInUse:1;                                     //0x7d
#            UCHAR UserStackWalkActive:1;                                    //0x7d
#            UCHAR SameThreadTransientFlagsReserved:5;                       //0x7d
#        };
#        CHAR SameThreadTransientFlags;                                      //0x7d
#    };
#    union
#    {
#        struct
#        {
#            UCHAR RunningNonRetpolineCode:1;                                //0x7e
#            UCHAR SpecCtrlSpare:7;                                          //0x7e
#        };
#        UCHAR SpecCtrl;                                                     //0x7e
#    };
#    ULONG SystemCallNumber;                                                 //0x80
#    ULONG ReadyTime;                                                        //0x84
#    VOID* FirstArgument;                                                    //0x88
#    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
#    union
#    {
#        struct _KAPC_STATE ApcState;                                        //0x98
#        struct
#        {
#            UCHAR ApcStateFill[43];                                         //0x98
#            CHAR Priority;                                                  //0xc3
#            ULONG UserIdealProcessor;                                       //0xc4
#        };
#    };
#    volatile LONGLONG WaitStatus;                                           //0xc8
#    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
#    union
#    {
#        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
#        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
#    };
#    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
#    VOID* Teb;                                                              //0xf0
#    ULONGLONG RelativeTimerBias;                                            //0xf8
#    struct _KTIMER Timer;                                                   //0x100
#    union
#    {
#        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
#        struct
#        {
#            UCHAR WaitBlockFill4[20];                                       //0x140
#            ULONG ContextSwitches;                                          //0x154
#        };
#        struct
#        {
#            UCHAR WaitBlockFill5[68];                                       //0x140
#            volatile UCHAR State;                                           //0x184
#            CHAR Spare13;                                                   //0x185
#            UCHAR WaitIrql;                                                 //0x186
#            CHAR WaitMode;                                                  //0x187
#        };
#        struct
#        {
#            UCHAR WaitBlockFill6[116];                                      //0x140
#            ULONG WaitTime;                                                 //0x1b4
#        };
#        struct
#        {
#            UCHAR WaitBlockFill7[164];                                      //0x140
#            union
#            {
#                struct
#                {
#                    SHORT KernelApcDisable;                                 //0x1e4
#                    SHORT SpecialApcDisable;                                //0x1e6
#                };
#                ULONG CombinedApcDisable;                                   //0x1e4
#            };
#        };
#        struct
#        {
#            UCHAR WaitBlockFill8[40];                                       //0x140
#            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
#        };
#        struct
#        {
#            UCHAR WaitBlockFill9[88];                                       //0x140
#            struct _XSTATE_SAVE* XStateSave;                                //0x198
#        };
#        struct
#        {
#            UCHAR WaitBlockFill10[136];                                     //0x140
#            VOID* volatile Win32Thread;                                     //0x1c8
#        };
#        struct
#        {
#            UCHAR WaitBlockFill11[176];                                     //0x140
#            ULONGLONG Spare18;                                              //0x1f0
#            ULONGLONG LastXStateSaveDebugInfo;                              //0x1f8
#        };
#    };
#    union
#    {
#        volatile LONG ThreadFlags2;                                         //0x200
#        struct
#        {
#            ULONG DisableKasan:1;                                           //0x200
#            ULONG AbContextSwitchState:1;                                   //0x200
#            ULONG ThreadFlags2Reserved:30;                                  //0x200
#        };
#    };
#    volatile UCHAR BamQosLevel;                                             //0x204
#    UCHAR HardwareFeedbackClass;                                            //0x205
#    UCHAR Spare23[2];                                                       //0x206
#    struct _LIST_ENTRY QueueListEntry;                                      //0x208
#    union
#    {
#        volatile ULONG NextProcessor;                                       //0x218
#        struct
#        {
#            ULONG NextProcessorNumber:31;                                   //0x218
#            ULONG SharedReadyQueue:1;                                       //0x218
#        };
#    };
#    LONG QueuePriority;                                                     //0x21c
#    struct _KPROCESS* Process;                                              //0x220
#    struct _KAFFINITY_EX* UserAffinity;                                     //0x228
#    USHORT UserAffinityPrimaryGroup;                                        //0x230
#    CHAR PreviousMode;                                                      //0x232
#    CHAR BasePriority;                                                      //0x233
#    union
#    {
#        CHAR PriorityDecrement;                                             //0x234
#        struct
#        {
#            UCHAR ForegroundBoost:4;                                        //0x234
#            UCHAR UnusualBoost:4;                                           //0x234
#        };
#    };
#    UCHAR Preempted;                                                        //0x235
#    UCHAR AdjustReason;                                                     //0x236
#    CHAR AdjustIncrement;                                                   //0x237
#    ULONGLONG AffinityVersion;                                              //0x238
#    struct _KAFFINITY_EX* Affinity;                                         //0x240
#    USHORT AffinityPrimaryGroup;                                            //0x248
#    UCHAR ApcStateIndex;                                                    //0x24a
#    UCHAR WaitBlockCount;                                                   //0x24b
#    ULONG IdealProcessor;                                                   //0x24c
#    ULONGLONG NpxState;                                                     //0x250
#    union
#    {
#        struct _KAPC_STATE SavedApcState;                                   //0x258
#        struct
#        {
#            UCHAR SavedApcStateFill[43];                                    //0x258
#            UCHAR WaitReason;                                               //0x283
#            CHAR SuspendCount;                                              //0x284
#            CHAR Saturation;                                                //0x285
#            USHORT SListFaultCount;                                         //0x286
#        };
#    };
#    union
#    {
#        struct _KAPC SchedulerApc;                                          //0x288
#        struct
#        {
#            UCHAR SchedulerApcFill1[3];                                     //0x288
#            UCHAR QuantumReset;                                             //0x28b
#        };
#        struct
#        {
#            UCHAR SchedulerApcFill2[4];                                     //0x288
#            ULONG KernelTime;                                               //0x28c
#        };
#        struct
#        {
#            UCHAR SchedulerApcFill3[64];                                    //0x288
#            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
#        };
#        struct
#        {
#            UCHAR SchedulerApcFill4[72];                                    //0x288
#            VOID* LegoData;                                                 //0x2d0
#        };
#        struct
#        {
#            UCHAR SchedulerApcFill5[83];                                    //0x288
#            UCHAR CallbackNestingLevel;                                     //0x2db
#            ULONG UserTime;                                                 //0x2dc
#        };
#    };
#    struct _KEVENT SuspendEvent;                                            //0x2e0
#    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
#    struct _LIST_ENTRY MutantListHead;                                      //0x308
#    union
#    {
#        struct
#        {
#            volatile UCHAR AbWaitEntryCount;                                //0x318
#            volatile UCHAR AbOwnedEntryCount;                               //0x319
#        };
#        volatile USHORT AbEntryCountValue;                                  //0x318
#    };
#    union
#    {
#        UCHAR FreezeFlags;                                                  //0x31a
#        struct
#        {
#            UCHAR FreezeCount2:1;                                           //0x31a
#            UCHAR FreezeNormal:1;                                           //0x31a
#            UCHAR FreezeDeep:1;                                             //0x31a
#        };
#    };
#    CHAR WobPriority;                                                       //0x31b
#    ULONG SecureThreadCookie;                                               //0x31c
#    VOID* SchedulerSharedSystemSlot;                                        //0x320
#    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
#    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
#    UCHAR PriorityFloorCounts[32];                                          //0x338
#    ULONG PriorityFloorSummary;                                             //0x358
#    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
#    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
#    volatile SHORT KeReferenceCount;                                        //0x364
#    CHAR DecayBoost;                                                        //0x366
#    UCHAR Spare6;                                                           //0x367
#    ULONG ForegroundLossTime;                                               //0x368
#    union
#    {
#        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
#        struct
#        {
#            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
#            ULONGLONG InGlobalForegroundList;                               //0x378
#        };
#    };
#    LONGLONG ReadOperationCount;                                            //0x380
#    LONGLONG WriteOperationCount;                                           //0x388
#    LONGLONG OtherOperationCount;                                           //0x390
#    LONGLONG ReadTransferCount;                                             //0x398
#    LONGLONG WriteTransferCount;                                            //0x3a0
#    LONGLONG OtherTransferCount;                                            //0x3a8
#    struct _KSCB* QueuedScb;                                                //0x3b0
#    volatile ULONG ThreadTimerDelay;                                        //0x3b8
#    USHORT Spare26;                                                         //0x3bc
#    volatile UCHAR PpmPolicy;                                               //0x3be
#    UCHAR Spare27;                                                          //0x3bf
#    ULONGLONG TracingPrivate[1];                                            //0x3c0
#    VOID* SchedulerAssist;                                                  //0x3c8
#    VOID* volatile AbWaitObject;                                            //0x3d0
#    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
#    ULONGLONG KernelWaitTime;                                               //0x3e0
#    ULONGLONG UserWaitTime;                                                 //0x3e8
#    union
#    {
#        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
#        struct
#        {
#            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
#            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
#        };
#    };
#    LONG SchedulerAssistPriorityFloor;                                      //0x400
#    LONG RealtimePriorityFloor;                                             //0x404
#    VOID* KernelShadowStack;                                                //0x408
#    VOID* KernelShadowStackInitial;                                         //0x410
#    VOID* KernelShadowStackBase;                                            //0x418
#    union _KERNEL_SHADOW_STACK_LIMIT KernelShadowStackLimit;                //0x420
#    ULONGLONG ExtendedFeatureDisableMask;                                   //0x428
#    ULONGLONG HgsFeedbackStartTime;                                         //0x430
#    ULONGLONG HgsFeedbackCycles;                                            //0x438
#    ULONG HgsInvalidFeedbackCount;                                          //0x440
#    ULONG HgsLowerPerfClassFeedbackCount;                                   //0x444
#    ULONG HgsHigherPerfClassFeedbackCount;                                  //0x448
#    volatile ULONG ModeHistory;                                             //0x44c
#    struct _SINGLE_LIST_ENTRY SystemAffinityTokenListHead;                  //0x450
#    VOID* IptSaveArea;                                                      //0x458
#    UCHAR ResourceIndex;                                                    //0x460
#    volatile UCHAR CoreIsolationReasons;                                    //0x461
#    UCHAR BamQosLevelFromAssistPage;                                        //0x462
#    UCHAR SecureCallCoreIsolationCount;                                     //0x463
#    ULONG SchedulerSharedOffset;                                            //0x464
#    struct _KSWAPPABLE_PAGE* SchedulerSharedSwappablePage;                  //0x468
#    struct _KLOCK_ENTRIES* KernelAbEntries;                                 //0x470
#    struct _KLOCK_ENTRIES* UserAbEntries;                                   //0x478
#    ULONGLONG KcsanThread;                                                  //0x480
#    ULONGLONG Padding[7];                                                   //0x488
#};
