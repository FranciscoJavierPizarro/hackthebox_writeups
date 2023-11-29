# Behind the Scenes
#challenge
#easy 
#reversing
#binary

We are given a program.

At first we try to execute it and it asks us for a password as a execution parameter.

We check if we can find something with strings, the command is `strings behindthescenes`

We find this but it is useless:

```
./challenge <password>
> HTB{%s}
:*3$"
```

Then with hexedit and the forward search `CTRL + S` we can perform a string search of challenge, finding the desired flag there. The command is `hexedit behindthescenes`
```
<password>.Itz._0n.Ly_.UD2.>
```

After removing the dots `Itz_0nLy_UD2`
