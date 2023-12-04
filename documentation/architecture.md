# Architecture
Comparison of system architectures and different layers

## Android
[Android architecture](photos/architecture-android.png)

Kernel - Linux  
Language - Dalvik (Java)  
Source model - Open Source

### Layers:  

*   **Kernel**      
        Management of core system services — process, memory, security, network

*   **HAL (Hardware Abstraction Layer)**  
        Interface for communicating the Android application/ framework with hardware-specific device drivers such as camera, Bluetooth, etc
*   **ART (Android Runtime)**  
        Optimizes garbage collection and power assumption and achieves high runtime performance.
*   **Native Libraries**  
        Helps in building user interface, graphics drawing and database access
*	**Application framework**  
        Features are database for storing data, support for audio, video and image formats, debugging tools
*	**System applications**  
        Native and third-party applications such as web browser, email, SMS messenger   
        Installed by the user

## iOS
[iOS architecture](photos/architecture-ios.png)

Kernel - OS X, UNIX  
Language -  Objective C  
Source model -  Closed, but iOS components are open source

### Layers:  

*   **Hardware**      
        Contains the physical chips

*   **Core OS**  
        Layer takes care of memory management
(allocation and de-allocation once the application has
finished using it), file management, network management,
etc
*   **Core services**  
        Provides several features like data
protection, iCloud storage, file sharing support, XML Support
features, SQLite database, In-App purchases, etc.

*   **Media**  
        Responsible for graphics, audio and video
capabilities
*	**Cocoa touch**  
        Provides key frameworks for building iOS
apps and defining their appearance