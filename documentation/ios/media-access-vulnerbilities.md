# Media access vulnerbilities

Since the field of attack for malicious or unaturhorized access to media is large, this section will be fucused mainly on perservation of integrity of data in rest.

![media access vulnerbilities](../photos/media-access.png)

**Media Files Directories**

- *Bundle Resources* - 
    When you include media files in your Xcode project, they are often added to the app's bundle. These files are read-only and can be accessed using the *NSBundle* class.[[2]](#resources)

- *Documents Directory* -
    User-created data that should be visible to the user. Backed up, but user can disable backup for specific apps
    This directory is writable, and you can use the *NSFileManager* class to manage files in this location.[[2]](#resources)

- *Caches Directory* -
    Semi-persistent cached files, not visible to the user and not backed up, is suitable for storing temporary files that can be regenerated. Use *NSFileManager* to manage files in the Caches directory.[[2]](#resources)
    
- *App Sandbox* -
    Persistent files necessary to run the app, not visible to the user. Backed up, but user can disable backup for specific apps.[[2]](#resources)
    iOS apps run in a sandboxed environment, meaning they have limited access to the device's file system. Each app has its own container, and one app cannot access the data of another app. 
    
**Frameworks Accessing Media Files**

- *UIKit Framework* - The UIKit framework provides classes like *UIImage* and *UIImageView* for working with images, and *UIImagePickerController* for accessing the device's camera or photo library. [[6]](#resources)

- *AVFoundation Framework* - For working with audio and video, the *AVFoundation framework* is commonly used. It provides classes like *AVPlayer* and *AVAsset* for playback and manipulation of audio and video content. [[6]](#resources)


## Threats
Risks of unauthorize resources access can be very compromising in therms of user privacy.</br>

- Invasion of privacy
- Reputational damage
- Data theft


## 1. Insecure Data Storage expoloits

If sensitive media files are stored in an insecure manner, for example without strong encryption, attackers may gain 
unauthorized access by directly accessing the file system. Without proper protection mechanisms application could easily leave media files susceptible to leaks and theft. 

Developers should ensure that access to these resources follows a secure policy (such as encrypting data before sending to the server). It is advisable to also make sure that there aren't 3rd party libraries in use that access resources insecurely. [[1]](#resources)


### Mitigations

- ***File Data Protection***

    When a new file is to be saved, a developer can choose from these options to better use of data protection:

    - Complete Protection (*NSFileProtectionComplete*) [[2]](#resources)
        - Only readable if device is unlocked.
        - File is closed when the device is locked.
        - Suitable for most apps and data.
    
    - Protected Unless Open (*NSFileProtectionCompleteUnlessOpen*) [[2]](#resources)
        - File can only be opened when the device is unlocked.
        - File is not closed when the device is locked.
        - File is encrypted when the last open handle is closed.
        - Suitable for data that is uploaded in the background

    - Protected Until First User Authentication (*NSFileProtectionCompleteUntilFirstUserAuthentication*) - default  [[2]](#resources)
        - File is inaccessible until the device is unlocked once after boot.
        - Suitable for background processes that should start ASAP after boot.
        - In general, all user data should be at least at this level.

    - No Protection (*NSFileProtectionNone*)  [[2]](#resources)
        - Suitable for certain applications that must access data immediately on boot without any user interaction. This encryption/decryption is handled by the OS and the keychain transparently. The relevant decryption key is created from the keychain when appropriate and erased from memory when appropriate

    Choosing the easiest or more prone to vulnerable options like, *NSFileProtectionNone* may lead to potential security risk.
    It is advisable to use *NSFileProtectionCompleteUnlessOpen* and *NSFileProtectionCompleteUntilFirstUserAuthentication* to have data protection on all files. [[1]](#resources)

    **Example:**

    Encrypting a file on the first write

    <pre>do {
    try data.write(to: fileURL, options: .completeFileProtection)
    }
    catch {
    // Handle errors.
    }</pre>

    Encrypting an existing file on disk
    <pre>do {
    try (fileURL as NSURL).setResourceValue( 
                    URLFileProtection.complete,
                    forKey: .fileProtectionKey)
    }
    catch {
    // Handle errors.
    }</pre>
    
- ***Data Encryption***

    Storing sensitive data locally on a user's device should be done securely to prevent unauthorized access. Apple provides several tools and mechanisms to ensure the safe storage of data, such as Keychain Services and Data Protection APIs.[[5]](#resources)

    - Keychain - iOS provide the system and applications with a secure key-value store API called the Keychain for storing sensitive secrets such as keys and passwords. The Keychain provides encrypted storage and permissioned access to the secret items.[[4]](#resources)
    
        Since it doesn't handle media files, for data encription is advisable to use Data Protection APIs.

    - Data Protection API allows you to encrypt files stored on the device, making them inaccessible when the device is locked.  [[5]](#resources)

        Code example:
        <pre>
        let fileURL = documentsDirectoryURL.appendingPathComponent("sensitive_data.txt")

        do {
            let data = "Sensitive data to be stored securely.".data(using: .utf8)
            try data?.write(to: fileURL, options: .completeFileProtection)
        } catch {
            print("Error writing data to file: \(error.localizedDescription)")
        }
        </pre>

- [***Third party library mitigations***](media-input-vulnerbilities.md/#mitigations-2)


## 2. Shared Resources Exploits:

If an app shares resources insecurely with other apps or the system, an attacker might exploit these shared resources to access media files (if files are placed in shared directories without appropriate permissions).

In addition to time-of-check–time-of-use problems, many other file operations are insecure. Programmers often make assumptions about the ownership, location, or attributes of a file that might not be true. 

For example, you might assume that you can always write to a file created by your program. 
However, if an attacker can change the permissions or flags on that file after you create it, and if you fail to check the result code after a write operation, you will not detect the fact that the file has been tampered with. [[3]](#resources)

Examples of insecure file operations include:
- writing to or reading from a file in a location writable by another user -> data leaks through Shared Resources
- failing to make the right checks for file type, device ID, links, and other settings before using a file
- failing to check the result code after a file operation
- assuming that if a file has a local pathname, it has to be a local file


### Mitigation

- ***App permissions***

    App permission includes additional privacy transparency and control features such as listing privacy-relevant permissions in the AppStore, allowing finer-grained access to photos, an OS supported recording indicator.

    Most of these features are focused on the privacy of users from app developers rather than from the phone itself, the relevant adversary under the threat model of forensics.[[4]](#resources)

- [***Sandboxing***](media-input-vulnerbilities.md/#mitigations-2)
- [***Jailbreak detection***](media-input-vulnerbilities.md/#mitigations-2)


## Resources

1. [iOS Mobile App Security — Part I: Best practices for iOS mobile developers](https://medium.com/@kavithakumarasamy89/ios-mobile-app-security-part-i-best-practices-for-ios-mobile-developers-1220748b1f3)
2. [Secure iOS application development](https://github.com/felixgr/secure-ios-app-dev)
3. [Secure Coding Guide - Types of Security Vulnerabilities](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/TypesSecVuln.html#//apple_ref/doc/uid/TP40002529-SW14)
4. [Data Security on Mobile Devices: Current State of the Art, Open Problems, and Proposed Solutions](https://arxiv.org/pdf/2105.12613.pdf)
5. [Enhancing Security in iOS Applications: Best Practices and Code Examples](https://medium.com/geekculture/enhancing-security-in-ios-applications-best-practices-and-code-examples-41cda1ff62fa)
6. [Architecture of IOS Operating System](https://www.geeksforgeeks.org/architecture-of-ios-operating-system/)
