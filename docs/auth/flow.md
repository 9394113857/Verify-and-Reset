# 🔐 Authentication Flow

## 📝 Registration Flow
1. User clicks **Sign Up** button.
2. System sends a **verification email**.
3. User is redirected to the **Login** page.

---

## 🔑 Login Flow

- If email is **not verified**:
  - "Your email is not verified. Please check your email."

- If email is **verified**:
  - "Your email has been verified. You can now log in."

- If login fails (invalid credentials):
  - "Login unsuccessful. Please check email and password."

- If login is successful and account is updated:
  - "Your account has been updated!"

> Note: Multiple users or parents may interact concurrently — this is acceptable for now.

---

## 🔄 Reset Password Flow

- If email does not exist in the system:
  - "There is no account with that email. You must register first."

- After entering a valid email and clicking **Reset Password**:
  - "An email has been sent with instructions to reset your password."

- After successfully resetting password:
  - "Your password has been updated! You are now able to log in."

---

## ⚠️ Developer Notes

- There might be an issue where the **same password is being overwritten**.
- This still needs to be developed and verified.
- Current flow is acceptable for the initial release.
