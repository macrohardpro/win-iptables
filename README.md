# win_iptables
A Windows version of iptables implemented based on WinDivert

# Roadmap

## README.md
- [简体中文](README_CN.md)

## Technology Stack

- **Programming Languages:**
  - C/C++: Using C++17 standard.
  - Python: auxiliary tools.

- **Libraries and Frameworks:**
  - PortBender: Core packet filtering library, used to implement rule matching and traffic control.
  - Windows API: For interacting with the operating system, such as creating services, managing processes, etc.

- **Build Tools:**
  - CMake: Cross-platform build system generator, used for configuring and compiling the project.
  - MSBuild: The default build system when compiling projects using Visual Studio.
  - Conan: Cross-platform C++ package manager

- **Version Control System:**
  - Git: Distributed version control system for code version management and collaborative development.

- **Testing Frameworks:**
  - Google Test: Unit testing framework for C++.

- **Continuous Integration/Continuous Deployment (CI/CD):**
  - GitHub Actions: Automates the build, test, and deployment process.

## Rule Management

- [ ] Basic Rule Operations
  - [ ] Add Rule
  - [ ] Remove Rule
  - [ ] Modify Existing Rule
  
- [ ] Chain Management
  - [ ] Create Custom Chains
  - [ ] Insert Rules into Specific Chains
  - [ ] Set Chain Policies

- [ ] Predefined Rule Sets
  - [ ] Allow All Traffic
  - [ ] Deny All Traffic
  - [ ] Common Security Configuration Templates

## Logging and Monitoring

- [ ] Real-time Log Viewing
  - [ ] Display Logs for Matching Rules Traffic
  - [ ] Filter and Search Log Entries

- [ ] Traffic Statistics
  - [ ] Network Connections Statistics
  - [ ] Data Transfer Volume Monitoring

- [ ] Alert System
  - [ ] Custom Trigger Conditions
  - [ ] Notification Methods (Pop-ups, Emails, etc.)

## User Interface

- [ ] Command Line Interface (CLI)
  - [ ] Support for Common iptables Commands
  - [ ] Interactive Help Documentation

- [ ] Graphical User Interface (GUI)
  - [ ] Visual Rule Editor
  - [ ] Status Panel and Dashboard

## Documentation and Support

- [ ] Online Help and Tutorials
  - [ ] Quick Start Guide
  - [ ] Detailed User Manual

- [ ] Community Forum and FAQ
  - [ ] User Exchange Platform
  - [ ] Solve Common Issues

## Testing and Validation

- [ ] Automated Test Suite
  - [ ] Unit Testing
  - [ ] Integration Testing

- [ ] User Feedback Loop
  - [ ] Beta Version Releases
  - [ ] Collect Improvement Suggestions

## Release and Updates

- [ ] Version Control
  - [ ] Regular Updates
  - [ ] Rollback Mechanism

- [ ] Multilingual Support
  - [ ] Internationalization and Localization
