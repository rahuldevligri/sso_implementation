SSO Implementation with SAML 2.0 🚀🔒
This repository demonstrates a Single Sign-On (SSO) implementation using SAML 2.0 in a Spring Boot Gradle project. It covers both SP to IDP and IDP to SP flows with detailed handling of SAML requests, responses, and authentication flows. 🎉

✨ Features & Achievements
🔑 Certificate & Key Management
Successfully generated X509Certificate and Private Key for signing and verifying SAML Responses. 🔐
Ensured secure communication between Identity Provider (IDP) and Service Provider (SP) using robust cryptographic mechanisms.
🛠️ Metadata Generation
Created SAML Metadata for both IDP and SP using SAML 2.0 libraries. 📜
Metadata includes details for secure SAML communication (endpoints, certificates, etc.).
🌐 IDP to SP Flow (Acting as an IDP)
1️⃣ IDP generates a SAMLResponse and sends it to SP.
2️⃣ Successfully implemented the flow where the user logs in at the IDP and is seamlessly authenticated at the SP without re-entering credentials. 🔁

🔄 SP to IDP Flow (With ADFS Integration)
1️⃣ User enters their email on the SP login page and clicks "Login with ADFS."
2️⃣ SP generates a SAMLRequest and sends it to the IDP.
3️⃣ IDP (ADFS) displays the login page where the user enters credentials.
4️⃣ Upon successful login, IDP generates a SAMLResponse and sends it to SP's API.
5️⃣ SP verifies and authenticates the SAMLResponse, allowing the user to access the application without logging in again. 🚀

✅ Core Functionalities Implemented
Generate SAMLRequest for SP → IDP flow.
Process SAMLResponse for IDP → SP flow.
Authenticate API to validate and verify SAML responses.
Verify Signatures on SAML responses using IDP's X509Certificate.
Sign SAML Responses using the generated private key and certificate.
⚙️ Technology Stack
Spring Boot (Gradle)
SAML 2.0 Libraries for request/response handling.
ADFS Integration for SP to IDP flow.
🤩 Why This Project?
This project showcases the complete implementation of SSO with SAML 2.0, covering secure communication between SP and IDP, metadata generation, and authentication flows. Whether you're exploring SSO or building an enterprise-level solution, this repository is your one-stop reference. 💡

Feel free to explore the code and adapt it for your projects! Contributions and feedback are always welcome. ❤️
