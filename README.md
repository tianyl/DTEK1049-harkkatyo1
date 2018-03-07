# DTEK1049-harkkatyo1

Harjoitustyön tavoite on toteuttaa junalippujen varaamiseen graafinen käyttöliittymä. Työ
tehdään kurssin alussa muodostetuissa 3-4 hengen ryhmissä. Sovelluksen toteuttamiseen
käytettävät ohjelmointikielet ja käyttöliittymätekniikat saa valita vapaasti. Harjoitustyö on
palautettava ma 30.4. viimeistään klo 23:59. Palautuksen tulee sisältää työn dokumentti
ja lähdekoodi tai linkki koodin sisältämään palveluun (esim. github, https://gitlab.utu.fi ).

Työn dokumentoinnin tulee kattaa koodi ja lyhyesti työprojektin kääntäminen, asennus
sekä käyttöönotto esimerkkikuvin valmiista järjestelmästä. Koodin dokumentointi tulee
tehdä Javadoc-tyylisesti (voi generoida työkalulla kuten javadoc / doxygen) ja dokumentaation
tulee kattaa julkiset liitännät (moduulit, paketit, luokat, rajapinnat, public-määreiset
jäsenet tai vastaavat funktiot ja tyypit).

Koosta dokumentit luettavan muotoon.
Tarkoitus on tehdä sovelluksesta mahdollisimman helppokäyttöinen ja selkeä, joten
muista käyttäjien ohjeistus, varmistusdialogit ja toimintojen helppous!

Oheisen tehtäväkuvauksen tarkoitus on antaa kuva toivotusta minimitoiminnallisuudesta,
mutta kuvauksesta saa poiketa taiteellisen vapauden ja hyvän käyttöliittymäsuunnittelun
nimissä, mikäli poikkeavan toiminnallisuuden seurauksena tehtävän vaikeusaste ei ratkaisevasti
muutu. Tehtävänantoon liittyvissä kysymyksissä voi ottaa yhteyttä kurssin järjestäjiin
(osoitteet yllä, jos et pääse esim. luennolle) tai kurssin Moodle-sivun kautta.


**Tehtäväkuvaus**
Junalippujen varaamisjärjestelmässä on kaksi erillistä käyttäjän roolia (ylläpitäjä ja käyttäjä)
ja näitä vastaavaa näkymää. Käyttäjätilin tietoihin on tallennettu tieto siitä, mitä rooleja
kukin käyttäjä on oikeutettu käyttämään. Peruskäyttäjällä ei luonnollisesti ole pääsyä
järjestelmän ylläpitoon, kun taas ylläpitäjällä oletusnäkymä on ylläpito, vaikka hänkin voi
varata halutessaan lippuja vaihtamalla käyttöliittymästä aktiivista rooliaan.

Järjestelmän käyttö alkaa kirjautumisruudulla. Käyttäjä voi luoda uuden käyttäjätilin tai
kirjautua sisään olemassa olevaan tiliin tunnus&salasana -parilla. Ylläpitäjän tili on luotu
etukäteen järjestelmään. Kirjautumista seuraa käyttäjän oletusroolin mukainen näkymä.
Järjestelmään voi kirjautua tätä ruutua käyttäen samaan aikaan useita eri käyttäjiä.

Käyttäjän näkymässä ensimmäinen vaihe on valita lähtö- ja saapumisasemat, lähtö- tai
saapumisaika sekä matkustajien määrä. Järjestelmä etsii tietokannastaan sopivimmat
yhteydet (joissa on riittävästi paikkoja jäljellä!) ja listaa ne. Yhteyksistä listataan lähtö- ja
saapumisajat halutulle yhteysvälille, matkan kesto, junan tyyppi ja kullekin yhteydelle
hinta ja junan palvelut. Sopivien yhteyksien puuttumisesta, aikamääreiden virheistä yms.
ongelmista tiedotetaan käyttäjää. Reitin valintaa seuraa paikkojen valinta. Tässä kohtaa
järjestelmä varaa määräajaksi paikat matkalta, jotta paikkoja ei voida varata kahdesti.
Paikan valinnassa tulee voida valita paikan erityistoiveet (allergia, lemmikki, pyörätuoli,
hiljainen, perhe- tai leikkitila) ja paikkatyypistä riippumatta istumapaikka (vaunu ja vaunukohtainen
graafinen istuinnäkymä). Jos toiveita ei voi toteuttaa, tästä ilmoitetaan. Valintaa
seuraa matkan maksaminen. Maksamisen voi suorittaa sovelluksella heti tai vasta
junassa. Maksun jälkeen järjestelmä poistaa varatut paikat pysyvästi ostettavien listalta.
Paikkatilanne välittyy heti muille järjestelmän samanaikaisille käyttäjille

Jokaisella käyttäjällä on myös asetusalinäkymä, jonka voi avata missä kohtaa tahansa.
Asetusnäkymästä voi päivittää tallennetut osoitetiedot, salasanan ja maksuvälinetiedot.

Ylläpitäjän näkymä koostuu alinäkymistä. Käyttäjäalinäkymässä voidaan lisätä,
poistaa ja muokata käyttäjän tietoja (ks. asetusnäkymä). Seuraavia näkymiä varten järjestelmä
olettaa, että jokainen vuorokausi on identtinen siten että kaikki liikennöivät junat
aloittavat aikaisintaan klo 0.00 ja lopettavat viimeistään klo 23.59, joka päivä liikennöidään
tismalleen samat reitit ja kaikilla liikennöivillä junilla on sama kokoonpano (vaunutyypit
ja määrät) joka päivä. Juna-alinäkymässä voidaan määrittää veturit, vaunutyypit
ja liikennöivien junien kokoonpano (mikä veturi ja vaunut). Jokaisen vaunutyypin paikkavalikoima
voidaan määrittää graafisesti. Jokaisella veturilla on jokin tunniste, esim.
UTU666. Reittialinäkymässä voidaan määrittää asemat ja asemien väliset yhteydet
(mikä veturi, lähtöaika ja asemien välinen matka-aika). Esim. UTU666 liikennöi Turusta
Helsinkiin klo 7.06. Reitin varrella voi olla väliasemia. Reitit voi yksinkertaistukseksi mää-
rittää niin, että väliasemat ovat vain ”koristeena” mukana ja reittivalinta tehdään päätepysäkkien
mukaan (jolloin esim. Turku-Helsinki -reitti ei automaattisesti tarjoa esim. reittiä
Turku-Salo). Reitit voi myös laskea jollakin graafien hakualgoritmilla. Matka-alinäkymässä
tarkasteltavissa ja muokattavissa ovat ostetut matkat. Matkoja voi listata esim.
päivä-, reitti- tai käyttäjätilikohtaisesti. Näkymästä tulisi nähdä esim. junien täyttöaste tai
korjata asiakkaan virheelliset matkavaraukset. Näkymä päivittyy varausten mukaisesti.
Vinkkejä ja huomioita:


**Vinkkejä ja huomioita**
Tehtävän toteutuksessa on luvallista ja erittäin toivottavaa käyttää ”oikoteitä” lopputuloksen
saamiseksi. Työtä arvioidaan kurssisuorituksena pelkästään käyttöliittymänsä osal -
ta. Esim. oikeaa tietokantajärjestelmää ei tarvitse käyttää työssä ja protokollien osalta
kannattaa pitäytyä käyttöliittymätekniikan valmiiksi tarjoamissa ratkaisuissa tai natiivin
käyttöliittymän tapauksessa jättää protokollakerros kokonaan pois. Tietokannan ja palvelimien
käyttöönotto voi olla yllättävän työlästä. Web-käyttöliittymän toteutuksessa oikean
tietokannan käyttö voi olla kuitenkin luonnollisin ja luontevin tapa ratkaista käyttöliittymään
liittyvä tiedon tallentamisen ja jakamisen ongelma. Esimerkiksi Java-sovellukseen
tietokannan sijaan oletusarvoiset lähtötiedot voi kovakoodata suoraan osaksi ohjelman
koodia. Jos teet näin, koita noudattaa MVC-paradigmaa tai vastaavaa tapaa tämän datan
erottelemiseksi mallin V- ja C-osista.

Järjestelmää on tarkoitus pystyä käyttämään eri käyttäjillä ja rooleilla samanaikaisesti.
Järjestelmän ei tarvitse reagoida ”tiukan reaktiivisesti” välittömästi vaan esim. näkymän
päivittyminen näkymän uudelleenlataamisen yhteydessä riittää. Samanaikaisuuden hallinta
edellyttää perusymmärrystä samanaikaisuustekniikoista, esim. säikeistä. Jos sinulla
on epäselvyyksiä säikeiden käytöstä, kysy kurssin järjestäjiltä, kurssitovereilta tai avaa
keskustelu kurssin Moodle-alueelle.

Web-käyttöliittymissä usean käyttäjän tuki on usein leivottu suoraan kehyksen
perustoimintoihin – avaa yksi näkymä esim. normaalisti selaimella ja toinen näkymä
incognito-tilaan tai eri laitteella (jos backend on säädetty kuuntelemaan ulkopuolisia yhteyksiä).

Java-käyttöliittymissä yksi mahdollisuus simuloida samanaikaisia käyttäjiä on paketoida
yhden käyttäjäistunnon kaikki tila näkyviin istunto-olion kautta ja luoda main()-rutiinissa
useita istunto-olioita. Istunto voi tarjota kirjautumisruudun esim. Swingissä oman
JFrame-olionsa kautta. Tällöin ei tarvitse murehtia siitä, miten tietoa välitetään yhdestä
JVM-virtuaalikoneen instanssista toiseen (esim. RMI/soketit). Saman virtuaalikoneen sisällä
tiedon samanaikainen käyttö kuitenkin vaatii asianmukaista lukitsemista (esim.
synchronized) säikeiden yhteydessä.

Työssä ei tarvitse tavoitella kaupallista viimeistelytasoa. Ehkä helpoin keino viimeistellyn
vaikutelman antamiseksi on tähdätä minimalismiin käyttöliittymän suunnittelussa – näin
parempi lopputulos voi syntyä vähemmällä työllä kuin alun perin oli tavoitteena. Toisaalta,
Blaise Pascal jo aikoinaan totesi ”Olisin kirjoittanut lyhemmin, jos minulla olisi ollut
enemmän aikaa”.

Tärkeintä on huomata, mikä harjoitteen tarkoituksena ylipäänsä on. Käyttöliittymän toteutuksessa
tärkein tavoite on kuvatun toimintalogiikan kuvaaminen valitun käyttöliittymätekniikan
mahdollistamin keinoin. Käyttäjäroolipohjainen malli on tyypillinen ”paradigma”
moderneissa käyttöliittymissä. Esimerkiksi varattavana paikan näkymät mahdollistavat
käyttöliittymän sisällön proseduraalisen generoinnin, mikä on näppärä tekniikka
ja huomattavasti elegantimpi kuin adhoc-kovakoodatut arvot. Samanaikaisuuden hallinta
haastaa opiskelemaan ja toteuttamaan tapahtumankäsittelyä niin kuin se yleensä käyttöliittymissä
ilmenee, enemmän tai vähemmän kaoottisesti.
Järjestelmän esittely:


Varmista että järjestelmässä on esittelyä varten valmiita muutamia/useita
• vetureita
• vaunutyyppejä
• useita reittejä
Aikataulujen ruuhkaisuuden demonstroimiseksi, tee järjestelmään hyvin runsas määrä
valmiita matkaostoja eri reiteille. Esim. satunnaismenetelmin silmukalla.
Laadi järjestelmään myös ainakin yhden normaalin sekä ylläpitokäyttäjän tilit.
