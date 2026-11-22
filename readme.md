# Prompt Sealer

Hello everyone! This project is one of my biggest project where technically this works as i expected but not as i expected. 

# What my project does.
A python cli tool build with typer which encrypts prompts 


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

```