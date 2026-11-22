# Prompt Sealer

Hello everyone! This project is one of my biggest project where technically this works as i expected but not as i expected. So this this concludes my version 1. { Version 2 Coming soon }

# What my project does.
A python cli tool build with typer which encrypts prompts. so that your personal prompts stays private.

# My Motive 

Consider two persons A and B, Person A wants to send a prompt which he use daily to Person B but if he shares it the prompt goes public and anyone can use it. so what my project does is. Person A installs my cli project and encrypts the prompt so it gives a encrypted file, now Person A shares that file to person B, now person B cannot read it coz its encrypted, now person B shares the encrypted file to ai { it could be anything } now ai scans that entire file and gives Access code A, now Person B shares the code to Person A then Person A sends them back to cli everthing is machine embedded so if we delete and reinstall cli even on the same machine the code changes, so after giving them cli gives Access code B, Now the final part the Access code B is shared to the ai and now ai can access the file, all these flow must happen within the time limit else prompt get deleted.

# Now for the future update

Everything works as expected but there is a major vulnerability which is once ai completed scanning the prompt stays inside ai and also if Person B asks to give the prompt easy to copy, then the ai blindly gives entire prompt. Tried all the methods and everything but still fails so on the version 2 i need to improve them rest all works as i expected.

# How to run this project.

```
git clone https://github.com/lucks-13/prompt-sealer.git
cd prompt-sealer
```
After Installing all the dependency to make sure everything works
```
prompt-sealer --help
```

# Availabe commands.

1. Initialize vault

```
prompt-sealer init
```

2. Check vault validity

```
prompt-sealer check
```

3. To seal a prompt

```
prompt-sealer seal prompt.txt sealed_prompt
```

4. Now Share sealed_prompt file to a ai { i tested using claude free chat / free plan coz its not working on chatgpt }

5. Now authorize the sealed prompt using Access Code A to get Access Code B

```
prompt-sealer authorize-prompt sealed_prompt.json <ACCESS_CODE_A>
```

6. Person A can also redeem the prompt

```
prompt-sealer redeem-prompt sealed_prompt <ACCESS_CODE_B> redeemed_prompt.txt
```

7. Now to Destroy the Vault so that existing encrypted prompt become undecryptable

```
prompt-sealer destroy
```
# AI Page

![Screen Shot](img/1.png)
![Screen Shot](img/2.png)
![Screen Shot](img/3.png)

# What I learned.

* Encrypting and Decrypting payload with AES-256-GCM, HKDF-SHA256 and HMAC-SHA256.
* Signing the file using Ed25519.
* Protecting local secrets with windows DPADI [ win32crypt ] and updating state files atomically.

# Ai Disclosure

I used AI alot but not for code generation coz this a very complicated project so technically i cannot build them without using ai { here ai means chatgpt, gemini, claude not ai agent like claude code, codex } so i use ai as learning assistant to understand cryptographic concepts, simplify code structure and troubleshoot errors, while building this project most of the code is written by me and with ai helping me to reason through design trade-offs and debug issues when i got struck.