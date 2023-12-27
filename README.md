# ZOSS-Tim1

R2 1/2023 - Nikola Jović  
R2 8/2023 - Katarina Komad

## Mobile security - iOS vs Android

This project aims to examine the challenges associated with mobile security, with a specific focus on the iOS and Android platforms as well as their comparison.

Since mobile devices have become an integral part of our daily lives, facilitating communication, entertainment, and productivity while also storing sensitive personal and corporate information, the need for robust mobile security has never been more critical. [[1]](https://www.hindawi.com/journals/misy/2020/8828078/)

Mobile security is a component of an overall digital security strategy, which is designed to protect portable devices. [[3]](https://www.forbes.com/advisor/business/what-is-mobile-security/) Security is a subject of study from two perspectives: technical and human factors. Therefore, we distinguish between security, which is generally a technical concern, and privacy, which is mostly a social concern. Naturally, these two notions are often related and interdependent. [[1]](https://www.hindawi.com/journals/misy/2020/8828078/) The focus here will be on the former.

Initial view is that no one mobile OS is inherently more secure than another. They each have strengths and weaknesses and quite often the more popular one can be more secure but due to popularity; that is where most hacker attacks are aimed. [[2]](https://sci-hub.se/10.1504/IJICS.2015.069205)

## Overview

Our research will be centered on the decomposition of both architectures to target modules, covering layers of operating systems, hardware and software.

The objective is to strategically analyze each target module and therefore identify potential threats and known vulnerabilities, describe specific attacks that occur, present the most current solutions or preventions, but also to potentially propose future strategies to strengthen the general security of mobile devices.

This exploration will strive to maintain a balance between conciseness and comprehensive coverage.

* ### [Modules](documentation/architecture.md)

  Document provides a comparative overview of the layered architectures of Android and iOS systems.  
  It highlights key components and fundamental principles guiding their designs.  
  These components will further be used as key points of analysis in terms of targeted modules in common threats and attacks.

* ### [IOS security analysis - media layer](documentation/ios/a-media-layer-analysis.md)
    - Identifies and documents potential threats iOS systems might face.
    - Gives detailed description of different types of attacks that could exploit vulnerabilities in the iOS systems.
    - Proposes strategies and countermeasures to mitigate the identified threats and defend against potential attacks.

* ### [Android security analysis - system applications](documentation/android-system-applications.md)
    - Identifies and documents potential threats Android systems might face.
    - Gives detailed description of different types of attacks that could exploit vulnerabilities in the Android systems.
    - Proposes strategies and countermeasures to mitigate the identified threats and defend against potential attacks.
  
* ### [Project references](documentation/project-references.md)

  All literature and research papers reviewed during development of this project are collected inside this document. It allows readers to explore the referenced materials for further in-depth understanding of the topics discussed.  

  It is sectioned in two parts:
    1. Reviewed and referenced papers 
    2. Future readings

## References

1. [Mobile Security: Threats and Best Practices](https://www.hindawi.com/journals/misy/2020/8828078/)
2. [Mobile device security](https://sci-hub.se/10.1504/IJICS.2015.069205)
3. [What Is Mobile Security? Definition & Best Practices](https://www.forbes.com/advisor/business/what-is-mobile-security/)
