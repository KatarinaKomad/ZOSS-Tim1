# Architecture

This document will explain the module decomposition, focusing on clarifying the architecture specific to Android and iOS operating systems, and will include a detailed overview of the layers that make up the architecture of each system. 

The Android operating system is characterized by its layered structure, encompassing components such as the application layer, framework layer, library layer, runtime layer, hardware abstract layer and kernel. 

Similarly, the iOS operating system has a layered architecture, including the Cocoa Touch layer, Media layer, Core Services, and the underlying Core OS layer. 

Through this system analysis, the document aims to provide a detailed insight into the hierarchical composition of these operating systems, facilitating the understanding of their design principles and functional interactions.

## Android

![Android architecture](photos/architecture-android.png)

Kernel - Linux  
Language - Dalvik (Java)  
Source model - Open Source

### Layers:  

*   **Kernel**
        <p>The kernel used by Android is a modified version of Linux kernel to carry out special requirements of the platform. Linux was chosen since it is open source, and has verified pathway evidence. Drivers are needed to be rewritten in various cases. Kernel is used for process management, memory management, networking, security settings etc. [[2]](https://www.ajtmr.com/papers/Vol5Issue2/Vol5Iss2_P4.pdf)</p>
        <p>These Linux kernels are combined with Android-specific patches to form *Android Common Kernels (ACKs)*. Newer ACKs are also known as GKI kernels. GKI kernels support the separation of the hardware-agnostic generic core kernel code and GKI modules from the hardware-specific vendor modules. The GKI kernel interacts with hardware-specific vendor modules containing system on a chip and board-specific code. The interaction between the GKI kernel and vendor modules is enabled by the Kernel Module Interface consisting of symbol lists identifying the functions and global data required by vendor modules. [[3]](https://source.android.com/docs/core/architecture/kernel)</p>

*   **HAL *(Hardware Abstraction Layer)***  
        <p>HAL acts as an interface for communicating the Android application/framework with hardware-specific device drivers such as camera, Bluetooth, etc. It is hardware-specific and its implementation varies from vendor to vendor. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)</p>
        <p>In Android 8.0 and higher, the lower-level layers are re-written to adopt a new, more modular architecture. These devices must support HALs written in *HIDL (HAL interface definition language)*. These HALs can be binderized or passthrough. In a Binderized HAL, the Android framework and HALs communicate with each other using binder *inter-process communication (IPC)* calls. [[4]](https://source.android.com/docs/core/architecture/hal)</p>

*   **ART *(Android Runtime)***  
        <p>*Android runtime* is the managed runtime used by applications and some system services on Android. ART and its predecessor Dalvik were originally created specifically for the Android project. ART as the runtime executes the Dalvik Executable format and Dex bytecode specification. [[5]](https://source.android.com/docs/core/runtime)</p> 
        <p>Dalvik uses *Just-in-Time (JIT) compilation*, each time an app is launched; some part of the source code needed for its execution is converted to machine code. In contrast to JIT compilation, ART compiles code *Ahead-of-Time (AOT)* i.e. an app is precompiled only once during its installation, which eliminates delay caused by JIT compilation, and the app is executed comparatively much faster. A benefit of AOT is that apps are executed with less CPU usage, which results in low battery wastage. [[2]](https://www.ajtmr.com/papers/Vol5Issue2/Vol5Iss2_P4.pdf)</p>

*   **Native Libraries**  
        <p>Core system services and different components of Android like ART and HAL are built from the native libraries, which are written in C/C++. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94) These libraries interact directly with the kernel or other interfaces and don't depend on a userspace-based HAL implementation and provide support in building user interface application framework, drawing graphics and accessing database. [[6]](https://source.android.com/docs/core/architecture)</p>

*   **Application framework**  
        <p>Android SDK provides tool and API libraries to develop applications on Android java. Important features are database for storing data, support for audio, video and image formats, debugging tools, etc. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94) 

    Application framework consists of:
    - *Activity Manager* - manages activity life cycle of apps. 
    - *Content Providers* - manage sharing data between apps. 
    - *Telephony Manager* - manage and access voice calls within application. 
    - *Window Manager* - oversees the creation, positioning, and management of windows on the device's screen.
    - *Package Manager* - provides access to information about installed applications. [[2]](https://www.ajtmr.com/papers/Vol5Issue2/Vol5Iss2_P4.pdf)</p>

*   **System applications**  
        <p>Applications are located at the top most layer of the Android stack. These consist of both native and third-party applications such as web browser, email, SMS messenger, etc., which are installed by the user. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)</p> 
        <p>System apps are pre-installed apps in the system partition with the ROM. In other words, a system app is simply an app placed under /system/app folder on an Android device. /system/app is a read-only folder. Android device users do not have access to this partition and they cannot directly install or uninstall apps to/from it. Apps such as camera, settings, messages, Google Play Store, etc. come pre-installed with the phone and manufacturers do not generally provide an option to remove such apps as this might impact the functioning of device.</p>

## iOS
![iOS architecture](photos/architecture-ios.png)

Kernel - OS X, BSD UNIX  
Language -  Objective C  
Source model -  Closed, but iOS components are open source

### Layers:  

*   **Hardware**      
        <p>The iOS hardware layer consists of the physical components within Apple devices, including custom-designed processors, memory, storage, displays, cameras, sensors, and connectivity features. These components work in unity to support the iOS operating system and deliver a high-performance and integrated user experience. This layer contains the physical chips, which are soldered to the iOS circuitry. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)</p>

*   **Core OS**  
        <p>The Core OS layer is the last layer of the iOS stack and sits directly on top of the device hardware providing the low level interface to the underlying hardware. System components of the Core OS Layer provides much of the same functionality as any other a UNIX multitasking kernel. [[7]](https://sci-hub.se/10.1109/EMES.2017.7980403)
        Amongst other things, the kernel is responsible for low level networking, input/output, inter-process communication, access to external accessories and the usual fundamental operating system services such as memory management (allocation and de-allocation once the application has finished using it), file system handling and threads, network management, etc. [[8]](https://rcet.org.in/uploads/academics/rohini_54027514709.pdf?fbclid=IwAR3z4GMmnzDOsN6vLClm3wIHh06NjAFile0NY7ayFDVGXgkE7iAYc9sg6Hc)</p>

*   **Core services**  
        <p>This forms the foundation layer on which above layers are built. It provides several features like data protection, iCloud storage, file sharing support, XML Support features, SQLite database, In-App purchases, etc. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)
    
    - The *CF Network framework* - provides a C-based interface to the TCP/IP networking protocol stack and low level access to BSD sockets. This enables application code to be written that works with HTTP, FTP and Domain Name servers and to establish secure and encrypted connections using *Secure Sockets Layer (SSL)* or *Transport Layer Security (TLS)*.  
    - The *Core Data framework* -  is provided to ease the creation of data modeling and storage in *Model-View-Controller (MVC)* based applications.  
    - The *Core Foundation* - is a C-based Framework that provides basic functionality such as data types, string manipulation, raw block data management, URL manipulation, threads and run loops, date and times, basic XML manipulation and port and socket communication.  
    - The *Core Location framework* - allows user to obtain the current geographical location of the device (latitude and longitude) and compass readings.  
    - The *EventKit framework* - is an API designed to provide applications with access to the calendar and alarms on the device.
     - The *System Configuration* - framework allows applications to access the network configuration settings of the device to establish information about the “reachability” of the device. [[8]](https://rcet.org.in/uploads/academics/rohini_54027514709.pdf?fbclid=IwAR3z4GMmnzDOsN6vLClm3wIHh06NjAFile0NY7ayFDVGXgkE7iAYc9sg6Hc)</p>

*   **Media**  
        <p>This layer is responsible for graphics, audio and video capabilities. Media layer consists of three different frameworks - *Graphic framework*, *Audio framework* and *Video framework*. These frameworks help in accessing photos and videos stored on the device, to manipulate the images through filters and provide support for 2D drawings. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)</p>

*   **Cocoa touch**  
        <p>Cocoa Touch is the user interface of the iOS operating system. This interface is fully object-oriented. Cocoa Touch contains the framework that enables one write an app on iOS OS and these frameworks define the aspect of the application. [[7]](https://sci-hub.se/10.1109/EMES.2017.7980403) It provides key frameworks for building iOS apps and defines their appearance. This layer is responsible for fundamental technologies like multitasking, touch-based input, push notifications, and many high-level system services. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)</p>

## References

[1] [Comparative analysis of Android and iOS from security viewpoint](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)

[2] [Android Architecture and Related Security Risks](https://www.ajtmr.com/papers/Vol5Issue2/Vol5Iss2_P4.pdf)

[3] [Android Kernel overview](https://source.android.com/docs/core/architecture/kernel)

[4] [Android Hardware abstraction layer overview](https://source.android.com/docs/core/architecture/hal)

[5] [Android Runtime (ART) and Dalvik](https://source.android.com/docs/core/runtime)

[6] [Android Architecture overview](https://source.android.com/docs/core/architecture)

[7] [Comparative Study of Google Android, Apple iOS and Microsoft Windows Phone Mobile Operating Systems ](https://sci-hub.se/10.1109/EMES.2017.7980403)

[8] [The IOS Core Services Layer & The IOS Core OS Layer - Rohini College Of Engineering & Technology](https://rcet.org.in/uploads/academics/rohini_54027514709.pdf?fbclid=IwAR3z4GMmnzDOsN6vLClm3wIHh06NjAFile0NY7ayFDVGXgkE7iAYc9sg6Hc)
