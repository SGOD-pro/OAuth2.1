**Step 1: Create the account normally (Sets your password)**
1. Since we just locked down /sign-up to only accept valid OAuth parameters (Task 5), you can temporarily comment out line 13 in frontend/src/pages/SignUp.tsx:
typescript
// if (!isValid) return <InvalidRequest reason="missing_params" />;
2. Go to http://localhost:5173/sign-up in your browser.
3. Sign up normally. This is where you set your password.
**Step 2: Promote the account to Admin**
Now that the account exists in the database, run the script to grant it admin privileges:
```bash
cd backend
npx ts-node scripts/make-admin.ts the-email-you-just-used@example.com

npx tsx scripts/make-admin.ts swyra@auth2.1.com
```
**Step 3: Log in to the Admin Panel**
1. Now you can go to http://localhost:5173/admin.
2.Because you aren't signed in, it will redirect you to /sign-in.
3. Sign in using the email and the password you set in Step 1.
4. Because the script made you an admin, Better Auth will now allow you into the /admin dashboard instead of redirecting you away!
(Don't forget to uncomment the if (!isValid) line in SignUp.tsx when you are done!)