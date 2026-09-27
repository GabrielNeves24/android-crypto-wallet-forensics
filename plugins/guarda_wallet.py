# VERSION: 2026-09-27-GUARDA-CRYPTOWALLET

__artifacts_v2__ = {
    "crypto_multiwallet_guarda": {
        "name": "Crypto Multiwallet Guarda Wallet",
        "description": "Parses com.crypto.multiwallet Android artifacts and produces a structured forensic report. Automatically inspects every RKStorage SQLite table and nested JSON layer, decrypts Guarda backup data when the internal backup.masterPassword is recovered, validates English BIP-39 mnemonics against the official 2048-word list and checksum, and presents wallet UUIDs, currencies, titles, public addresses, balances, private keys, derivation metadata and subwallets in a readable summary.",
        "author": "Gabriel Neves / ChatGPT",
        "creation_date": "2026-06-30",
        "last_update_date": "2026-09-27",
        "requirements": "PyCryptodome (included in ALEAPP); cryptography is supported as a fallback",
        "category": "Cryptocurrency",
        "notes": "WARNING: SENSITIVE FORENSIC OUTPUT. The generated HTML/TSV may contain mnemonic phrases, private keys, internal master passwords and other wallet secrets. The raw encryptedData ciphertext is represented by length and SHA-256 instead of being printed. Use only on authorised evidence and protect the output accordingly. Decrypts OpenSSL/CryptoJS Salted__ AES-256-CBC data only when the internal backup.masterPassword is present in the evidence, either in the same RKStorage or in another acquisition containing the identical encryptedData blob. It does not assume that the user's unlock password is this internal value.",
        "paths": (
            # Full extraction or parent folder containing the app package
            "*/com.crypto.multiwallet/databases/RKStorage",
            "*/guarda_*rkstorage.json",
            "*/RKStorage*.json",
            "*/com.crypto.multiwallet/files/*/backup*.txt",
            "*/com.crypto.multiwallet/files/mmkv/mmkv.default",
            "*/com.crypto.multiwallet/files/mmkv/mmkv.default.crc",
            "*/com.crypto.multiwallet/shared_prefs/com.crypto.multiwallet_preferences.xml",
            "*/com.crypto.multiwallet/shared_prefs/react-native-device-info.xml",
            "*/com.crypto.multiwallet/shared_prefs/WebViewChromiumPrefs.xml",
            "*/com.crypto.multiwallet/app_webview/Default/Cookies",
            "*/com.crypto.multiwallet/app_webview/Default/Local Storage/leveldb/000*.log",
            # Direct package-root selection support
            "databases/RKStorage",
            "guarda_*rkstorage.json",
            "RKStorage*.json",
            "files/*/backup*.txt",
            "files/mmkv/mmkv.default",
            "files/mmkv/mmkv.default.crc",
            "shared_prefs/com.crypto.multiwallet_preferences.xml",
            "shared_prefs/react-native-device-info.xml",
            "shared_prefs/WebViewChromiumPrefs.xml",
            "app_webview/Default/Cookies",
            "app_webview/Default/Local Storage/leveldb/000*.log",
        ),
        "output_types": ["html", "tsv"],
        "artifact_icon": "coins",
        "function": "crypto_multiwallet_guarda",
    }
}

import base64
import csv
import datetime
import hashlib
import html
import json
import os
import pathlib
import re
import sqlite3
import sys
import unicodedata
import xml.etree.ElementTree as ET

try:
    from Crypto.Cipher import AES as PYCRYPTO_AES
    from Crypto.Util.Padding import unpad as pycrypto_unpad
except Exception:
    PYCRYPTO_AES = None
    pycrypto_unpad = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except Exception:
    Cipher = None
    algorithms = None
    modes = None
    PKCS7 = None

try:
    from scripts.ilapfuncs import artifact_processor, logfunc, tsv
    from scripts.artifact_report import ArtifactHtmlReport
except Exception:
    ArtifactHtmlReport = None

    def artifact_processor(func):
        return func

    def logfunc(message):
        print(message)

    def tsv(report_folder, data_headers, data_list, tsvname, source_file=None):
        # Standalone fallback used only when the plugin is executed outside ALEAPP.
        pass


APP_PACKAGE = "com.crypto.multiwallet"
BIP39_ENGLISH_WORDS = """
abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
account
accuse
achieve
acid
acoustic
acquire
across
act
action
actor
actress
actual
adapt
add
addict
address
adjust
admit
adult
advance
advice
aerobic
affair
afford
afraid
again
age
agent
agree
ahead
aim
air
airport
aisle
alarm
album
alcohol
alert
alien
all
alley
allow
almost
alone
alpha
already
also
alter
always
amateur
amazing
among
amount
amused
analyst
anchor
ancient
anger
angle
angry
animal
ankle
announce
annual
another
answer
antenna
antique
anxiety
any
apart
apology
appear
apple
approve
april
arch
arctic
area
arena
argue
arm
armed
armor
army
around
arrange
arrest
arrive
arrow
art
artefact
artist
artwork
ask
aspect
assault
asset
assist
assume
asthma
athlete
atom
attack
attend
attitude
attract
auction
audit
august
aunt
author
auto
autumn
average
avocado
avoid
awake
aware
away
awesome
awful
awkward
axis
baby
bachelor
bacon
badge
bag
balance
balcony
ball
bamboo
banana
banner
bar
barely
bargain
barrel
base
basic
basket
battle
beach
bean
beauty
because
become
beef
before
begin
behave
behind
believe
below
belt
bench
benefit
best
betray
better
between
beyond
bicycle
bid
bike
bind
biology
bird
birth
bitter
black
blade
blame
blanket
blast
bleak
bless
blind
blood
blossom
blouse
blue
blur
blush
board
boat
body
boil
bomb
bone
bonus
book
boost
border
boring
borrow
boss
bottom
bounce
box
boy
bracket
brain
brand
brass
brave
bread
breeze
brick
bridge
brief
bright
bring
brisk
broccoli
broken
bronze
broom
brother
brown
brush
bubble
buddy
budget
buffalo
build
bulb
bulk
bullet
bundle
bunker
burden
burger
burst
bus
business
busy
butter
buyer
buzz
cabbage
cabin
cable
cactus
cage
cake
call
calm
camera
camp
can
canal
cancel
candy
cannon
canoe
canvas
canyon
capable
capital
captain
car
carbon
card
cargo
carpet
carry
cart
case
cash
casino
castle
casual
cat
catalog
catch
category
cattle
caught
cause
caution
cave
ceiling
celery
cement
census
century
cereal
certain
chair
chalk
champion
change
chaos
chapter
charge
chase
chat
cheap
check
cheese
chef
cherry
chest
chicken
chief
child
chimney
choice
choose
chronic
chuckle
chunk
churn
cigar
cinnamon
circle
citizen
city
civil
claim
clap
clarify
claw
clay
clean
clerk
clever
click
client
cliff
climb
clinic
clip
clock
clog
close
cloth
cloud
clown
club
clump
cluster
clutch
coach
coast
coconut
code
coffee
coil
coin
collect
color
column
combine
come
comfort
comic
common
company
concert
conduct
confirm
congress
connect
consider
control
convince
cook
cool
copper
copy
coral
core
corn
correct
cost
cotton
couch
country
couple
course
cousin
cover
coyote
crack
cradle
craft
cram
crane
crash
crater
crawl
crazy
cream
credit
creek
crew
cricket
crime
crisp
critic
crop
cross
crouch
crowd
crucial
cruel
cruise
crumble
crunch
crush
cry
crystal
cube
culture
cup
cupboard
curious
current
curtain
curve
cushion
custom
cute
cycle
dad
damage
damp
dance
danger
daring
dash
daughter
dawn
day
deal
debate
debris
decade
december
decide
decline
decorate
decrease
deer
defense
define
defy
degree
delay
deliver
demand
demise
denial
dentist
deny
depart
depend
deposit
depth
deputy
derive
describe
desert
design
desk
despair
destroy
detail
detect
develop
device
devote
diagram
dial
diamond
diary
dice
diesel
diet
differ
digital
dignity
dilemma
dinner
dinosaur
direct
dirt
disagree
discover
disease
dish
dismiss
disorder
display
distance
divert
divide
divorce
dizzy
doctor
document
dog
doll
dolphin
domain
donate
donkey
donor
door
dose
double
dove
draft
dragon
drama
drastic
draw
dream
dress
drift
drill
drink
drip
drive
drop
drum
dry
duck
dumb
dune
during
dust
dutch
duty
dwarf
dynamic
eager
eagle
early
earn
earth
easily
east
easy
echo
ecology
economy
edge
edit
educate
effort
egg
eight
either
elbow
elder
electric
elegant
element
elephant
elevator
elite
else
embark
embody
embrace
emerge
emotion
employ
empower
empty
enable
enact
end
endless
endorse
enemy
energy
enforce
engage
engine
enhance
enjoy
enlist
enough
enrich
enroll
ensure
enter
entire
entry
envelope
episode
equal
equip
era
erase
erode
erosion
error
erupt
escape
essay
essence
estate
eternal
ethics
evidence
evil
evoke
evolve
exact
example
excess
exchange
excite
exclude
excuse
execute
exercise
exhaust
exhibit
exile
exist
exit
exotic
expand
expect
expire
explain
expose
express
extend
extra
eye
eyebrow
fabric
face
faculty
fade
faint
faith
fall
false
fame
family
famous
fan
fancy
fantasy
farm
fashion
fat
fatal
father
fatigue
fault
favorite
feature
february
federal
fee
feed
feel
female
fence
festival
fetch
fever
few
fiber
fiction
field
figure
file
film
filter
final
find
fine
finger
finish
fire
firm
first
fiscal
fish
fit
fitness
fix
flag
flame
flash
flat
flavor
flee
flight
flip
float
flock
floor
flower
fluid
flush
fly
foam
focus
fog
foil
fold
follow
food
foot
force
forest
forget
fork
fortune
forum
forward
fossil
foster
found
fox
fragile
frame
frequent
fresh
friend
fringe
frog
front
frost
frown
frozen
fruit
fuel
fun
funny
furnace
fury
future
gadget
gain
galaxy
gallery
game
gap
garage
garbage
garden
garlic
garment
gas
gasp
gate
gather
gauge
gaze
general
genius
genre
gentle
genuine
gesture
ghost
giant
gift
giggle
ginger
giraffe
girl
give
glad
glance
glare
glass
glide
glimpse
globe
gloom
glory
glove
glow
glue
goat
goddess
gold
good
goose
gorilla
gospel
gossip
govern
gown
grab
grace
grain
grant
grape
grass
gravity
great
green
grid
grief
grit
grocery
group
grow
grunt
guard
guess
guide
guilt
guitar
gun
gym
habit
hair
half
hammer
hamster
hand
happy
harbor
hard
harsh
harvest
hat
have
hawk
hazard
head
health
heart
heavy
hedgehog
height
hello
helmet
help
hen
hero
hidden
high
hill
hint
hip
hire
history
hobby
hockey
hold
hole
holiday
hollow
home
honey
hood
hope
horn
horror
horse
hospital
host
hotel
hour
hover
hub
huge
human
humble
humor
hundred
hungry
hunt
hurdle
hurry
hurt
husband
hybrid
ice
icon
idea
identify
idle
ignore
ill
illegal
illness
image
imitate
immense
immune
impact
impose
improve
impulse
inch
include
income
increase
index
indicate
indoor
industry
infant
inflict
inform
inhale
inherit
initial
inject
injury
inmate
inner
innocent
input
inquiry
insane
insect
inside
inspire
install
intact
interest
into
invest
invite
involve
iron
island
isolate
issue
item
ivory
jacket
jaguar
jar
jazz
jealous
jeans
jelly
jewel
job
join
joke
journey
joy
judge
juice
jump
jungle
junior
junk
just
kangaroo
keen
keep
ketchup
key
kick
kid
kidney
kind
kingdom
kiss
kit
kitchen
kite
kitten
kiwi
knee
knife
knock
know
lab
label
labor
ladder
lady
lake
lamp
language
laptop
large
later
latin
laugh
laundry
lava
law
lawn
lawsuit
layer
lazy
leader
leaf
learn
leave
lecture
left
leg
legal
legend
leisure
lemon
lend
length
lens
leopard
lesson
letter
level
liar
liberty
library
license
life
lift
light
like
limb
limit
link
lion
liquid
list
little
live
lizard
load
loan
lobster
local
lock
logic
lonely
long
loop
lottery
loud
lounge
love
loyal
lucky
luggage
lumber
lunar
lunch
luxury
lyrics
machine
mad
magic
magnet
maid
mail
main
major
make
mammal
man
manage
mandate
mango
mansion
manual
maple
marble
march
margin
marine
market
marriage
mask
mass
master
match
material
math
matrix
matter
maximum
maze
meadow
mean
measure
meat
mechanic
medal
media
melody
melt
member
memory
mention
menu
mercy
merge
merit
merry
mesh
message
metal
method
middle
midnight
milk
million
mimic
mind
minimum
minor
minute
miracle
mirror
misery
miss
mistake
mix
mixed
mixture
mobile
model
modify
mom
moment
monitor
monkey
monster
month
moon
moral
more
morning
mosquito
mother
motion
motor
mountain
mouse
move
movie
much
muffin
mule
multiply
muscle
museum
mushroom
music
must
mutual
myself
mystery
myth
naive
name
napkin
narrow
nasty
nation
nature
near
neck
need
negative
neglect
neither
nephew
nerve
nest
net
network
neutral
never
news
next
nice
night
noble
noise
nominee
noodle
normal
north
nose
notable
note
nothing
notice
novel
now
nuclear
number
nurse
nut
oak
obey
object
oblige
obscure
observe
obtain
obvious
occur
ocean
october
odor
off
offer
office
often
oil
okay
old
olive
olympic
omit
once
one
onion
online
only
open
opera
opinion
oppose
option
orange
orbit
orchard
order
ordinary
organ
orient
original
orphan
ostrich
other
outdoor
outer
output
outside
oval
oven
over
own
owner
oxygen
oyster
ozone
pact
paddle
page
pair
palace
palm
panda
panel
panic
panther
paper
parade
parent
park
parrot
party
pass
patch
path
patient
patrol
pattern
pause
pave
payment
peace
peanut
pear
peasant
pelican
pen
penalty
pencil
people
pepper
perfect
permit
person
pet
phone
photo
phrase
physical
piano
picnic
picture
piece
pig
pigeon
pill
pilot
pink
pioneer
pipe
pistol
pitch
pizza
place
planet
plastic
plate
play
please
pledge
pluck
plug
plunge
poem
poet
point
polar
pole
police
pond
pony
pool
popular
portion
position
possible
post
potato
pottery
poverty
powder
power
practice
praise
predict
prefer
prepare
present
pretty
prevent
price
pride
primary
print
priority
prison
private
prize
problem
process
produce
profit
program
project
promote
proof
property
prosper
protect
proud
provide
public
pudding
pull
pulp
pulse
pumpkin
punch
pupil
puppy
purchase
purity
purpose
purse
push
put
puzzle
pyramid
quality
quantum
quarter
question
quick
quit
quiz
quote
rabbit
raccoon
race
rack
radar
radio
rail
rain
raise
rally
ramp
ranch
random
range
rapid
rare
rate
rather
raven
raw
razor
ready
real
reason
rebel
rebuild
recall
receive
recipe
record
recycle
reduce
reflect
reform
refuse
region
regret
regular
reject
relax
release
relief
rely
remain
remember
remind
remove
render
renew
rent
reopen
repair
repeat
replace
report
require
rescue
resemble
resist
resource
response
result
retire
retreat
return
reunion
reveal
review
reward
rhythm
rib
ribbon
rice
rich
ride
ridge
rifle
right
rigid
ring
riot
ripple
risk
ritual
rival
river
road
roast
robot
robust
rocket
romance
roof
rookie
room
rose
rotate
rough
round
route
royal
rubber
rude
rug
rule
run
runway
rural
sad
saddle
sadness
safe
sail
salad
salmon
salon
salt
salute
same
sample
sand
satisfy
satoshi
sauce
sausage
save
say
scale
scan
scare
scatter
scene
scheme
school
science
scissors
scorpion
scout
scrap
screen
script
scrub
sea
search
season
seat
second
secret
section
security
seed
seek
segment
select
sell
seminar
senior
sense
sentence
series
service
session
settle
setup
seven
shadow
shaft
shallow
share
shed
shell
sheriff
shield
shift
shine
ship
shiver
shock
shoe
shoot
shop
short
shoulder
shove
shrimp
shrug
shuffle
shy
sibling
sick
side
siege
sight
sign
silent
silk
silly
silver
similar
simple
since
sing
siren
sister
situate
six
size
skate
sketch
ski
skill
skin
skirt
skull
slab
slam
sleep
slender
slice
slide
slight
slim
slogan
slot
slow
slush
small
smart
smile
smoke
smooth
snack
snake
snap
sniff
snow
soap
soccer
social
sock
soda
soft
solar
soldier
solid
solution
solve
someone
song
soon
sorry
sort
soul
sound
soup
source
south
space
spare
spatial
spawn
speak
special
speed
spell
spend
sphere
spice
spider
spike
spin
spirit
split
spoil
sponsor
spoon
sport
spot
spray
spread
spring
spy
square
squeeze
squirrel
stable
stadium
staff
stage
stairs
stamp
stand
start
state
stay
steak
steel
stem
step
stereo
stick
still
sting
stock
stomach
stone
stool
story
stove
strategy
street
strike
strong
struggle
student
stuff
stumble
style
subject
submit
subway
success
such
sudden
suffer
sugar
suggest
suit
summer
sun
sunny
sunset
super
supply
supreme
sure
surface
surge
surprise
surround
survey
suspect
sustain
swallow
swamp
swap
swarm
swear
sweet
swift
swim
swing
switch
sword
symbol
symptom
syrup
system
table
tackle
tag
tail
talent
talk
tank
tape
target
task
taste
tattoo
taxi
teach
team
tell
ten
tenant
tennis
tent
term
test
text
thank
that
theme
then
theory
there
they
thing
this
thought
three
thrive
throw
thumb
thunder
ticket
tide
tiger
tilt
timber
time
tiny
tip
tired
tissue
title
toast
tobacco
today
toddler
toe
together
toilet
token
tomato
tomorrow
tone
tongue
tonight
tool
tooth
top
topic
topple
torch
tornado
tortoise
toss
total
tourist
toward
tower
town
toy
track
trade
traffic
tragic
train
transfer
trap
trash
travel
tray
treat
tree
trend
trial
tribe
trick
trigger
trim
trip
trophy
trouble
truck
true
truly
trumpet
trust
truth
try
tube
tuition
tumble
tuna
tunnel
turkey
turn
turtle
twelve
twenty
twice
twin
twist
two
type
typical
ugly
umbrella
unable
unaware
uncle
uncover
under
undo
unfair
unfold
unhappy
uniform
unique
unit
universe
unknown
unlock
until
unusual
unveil
update
upgrade
uphold
upon
upper
upset
urban
urge
usage
use
used
useful
useless
usual
utility
vacant
vacuum
vague
valid
valley
valve
van
vanish
vapor
various
vast
vault
vehicle
velvet
vendor
venture
venue
verb
verify
version
very
vessel
veteran
viable
vibrant
vicious
victory
video
view
village
vintage
violin
virtual
virus
visa
visit
visual
vital
vivid
vocal
voice
void
volcano
volume
vote
voyage
wage
wagon
wait
walk
wall
walnut
want
warfare
warm
warrior
wash
wasp
waste
water
wave
way
wealth
weapon
wear
weasel
weather
web
wedding
weekend
weird
welcome
west
wet
whale
what
wheat
wheel
when
where
whip
whisper
wide
width
wife
wild
will
win
window
wine
wing
wink
winner
winter
wire
wisdom
wise
wish
witness
wolf
woman
wonder
wood
wool
word
work
world
worry
worth
wrap
wreck
wrestle
wrist
write
wrong
yard
year
yellow
you
young
youth
zebra
zero
zone
zoo
""".split()
BIP39_ENGLISH_INDEX = {word: index for index, word in enumerate(BIP39_ENGLISH_WORDS)}
SENSITIVE_KEYS = {
    "privatekey", "private_key", "seed", "mnemonic", "password", "masterpassword",
    "spendkey", "stakekey", "wif", "xprv", "secret", "encrypteddata",
}

EVM_RE = re.compile(r"(?<![0-9A-Fa-f])0x[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
BTC_RE = re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{25,90}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![A-Za-z0-9])", re.I)
BNB_RE = re.compile(r"(?<![a-z0-9])bnb1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{30,70}(?![a-z0-9])", re.I)
TRON_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])T[1-9A-HJ-NP-Za-km-z]{33}(?![1-9A-HJ-NP-Za-km-z])")
XRP_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])r[1-9A-HJ-NP-Za-km-z]{24,34}(?![1-9A-HJ-NP-Za-km-z])")
ADA_RE = re.compile(r"(?<![a-z0-9])(?:addr1|stake1)[0-9a-z]{45,120}(?![a-z0-9])", re.I)
DOGE_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}(?![1-9A-HJ-NP-Za-km-z])")

ADDRESS_REGEXES = [
    ("Ethereum/EVM", EVM_RE),
    ("Bitcoin", BTC_RE),
    ("BNB Beacon", BNB_RE),
    ("TRON", TRON_RE),
    ("XRP", XRP_RE),
    ("Cardano", ADA_RE),
    ("Dogecoin", DOGE_RE),
]


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_text(value):
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def _safe_size(path):
    try:
        return pathlib.Path(path).stat().st_size
    except Exception:
        return 0


def _safe_rel(path):
    # Keep full path as source; ALEAPP can render it. This helper normalizes only for checks.
    return str(path).replace("\\", "/")


def _safe_json_loads(value, max_depth=8):
    """Decode bytes and repeatedly nested JSON strings, then recurse into containers."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None

    decoded_any = isinstance(value, (dict, list))
    current = value
    for _ in range(max_depth):
        if not isinstance(current, str):
            break
        candidate = current.strip().lstrip("\ufeff")
        if not candidate:
            break
        # Only decode JSON containers or explicitly quoted nested JSON. This
        # preserves digit-only passwords/private keys as strings.
        if candidate[0] not in "{[\"":
            break
        try:
            current = json.loads(candidate)
            decoded_any = True
        except Exception:
            break

    def decode_child(item):
        if max_depth <= 0:
            return item
        decoded = _safe_json_loads(item, max_depth - 1)
        return item if decoded is None else decoded

    if isinstance(current, dict):
        return {key: decode_child(item) for key, item in current.items()}
    if isinstance(current, list):
        return [decode_child(item) for item in current]
    return current if decoded_any else None


def _quote_sql_identifier(identifier):
    return '"' + str(identifier).replace('"', '""') + '"'


def _read_rkstorage_records(path):
    """Return (table diagnostics, possible key/value records) from any SQLite schema."""
    table_info = []
    records = []
    with _open_sqlite_readonly(path) as con:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()]
        for table in tables:
            quoted_table = _quote_sql_identifier(table)
            columns = cur.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            column_names = [column[1] for column in columns]
            column_types = {column[1]: str(column[2] or "").upper() for column in columns}
            row_count = cur.execute(f"SELECT COUNT(*) FROM {quoted_table}").fetchone()[0]
            table_info.append((table, column_names, row_count))

            lowered = {name.lower(): name for name in column_names}
            key_column = next((lowered[name] for name in ("key", "name", "storage_key", "id") if name in lowered), None)
            value_column = next((lowered[name] for name in ("value", "data", "json", "storage_value") if name in lowered), None)

            if key_column and value_column:
                sql = (f"SELECT {_quote_sql_identifier(key_column)}, "
                       f"{_quote_sql_identifier(value_column)} FROM {quoted_table}")
                for key, value in cur.execute(sql).fetchall():
                    records.append((table, str(key), value))
                continue

            candidate_columns = [
                name for name in column_names
                if (any(type_name in column_types.get(name, "") for type_name in ("TEXT", "BLOB"))
                    or not column_types.get(name, ""))
            ]
            for column_name in candidate_columns:
                sql = f"SELECT rowid, {_quote_sql_identifier(column_name)} FROM {quoted_table}"
                for rowid, value in cur.execute(sql).fetchall():
                    records.append((table, f"rowid={rowid}.{column_name}", value))
    return table_info, records


def _find_backup_objects(value):
    """Find Redux backup objects regardless of JSON nesting or encoding layers."""
    root = _safe_json_loads(value)
    if root is None:
        return []
    found = []
    seen = set()

    def add(path, obj):
        if not isinstance(obj, dict):
            return
        marker = id(obj)
        if marker in seen:
            return
        seen.add(marker)
        found.append((path, obj))

    def walk(item, path="root"):
        if isinstance(item, dict):
            keys = {str(key).lower() for key in item.keys()}
            if "encrypteddata" in keys or "masterpassword" in keys:
                add(path, item)
            for key, child in item.items():
                child_path = f"{path}.{key}"
                if str(key).lower() == "backup":
                    add(child_path, child)
                walk(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(root)
    return found


def _open_sqlite_readonly(path):
    """Open an evidence database without permitting SQLite writes or journals."""
    path_string = os.path.abspath(str(path))
    if os.name == "nt":
        # ALEAPP may supply Win32 extended-length paths (\\?\C:\...). SQLite's
        # URI parser expects the prefix removed and forward slashes.
        if path_string.startswith("\\\\?\\"):
            path_string = path_string[4:]
        uri = "file:/" + path_string.replace("\\", "/") + "?mode=ro"
    else:
        uri = pathlib.Path(path_string).as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
    """Reproduce the legacy OpenSSL/CryptoJS EVP_BytesToKey MD5 derivation."""
    password_bytes = str(password).encode("utf-8")
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password_bytes + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len:key_len + iv_len]


def _aes256_cbc_decrypt(ciphertext, key, iv):
    if PYCRYPTO_AES is not None and pycrypto_unpad is not None:
        padded = PYCRYPTO_AES.new(key, PYCRYPTO_AES.MODE_CBC, iv).decrypt(ciphertext)
        return pycrypto_unpad(padded, 16)

    if Cipher is not None and PKCS7 is not None:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    raise RuntimeError("No AES backend available (install PyCryptodome)")


def _decrypt_cryptojs_backup(encrypted_base64, master_password):
    """Return (parsed JSON, plaintext SHA-256) without persisting plaintext."""
    if not isinstance(encrypted_base64, str) or not encrypted_base64:
        raise ValueError("encryptedData is empty")
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("masterPassword is empty")

    try:
        raw = base64.b64decode(encrypted_base64, validate=True)
    except Exception as ex:
        raise ValueError("encryptedData is not valid Base64") from ex

    if len(raw) < 32 or raw[:8] != b"Salted__":
        raise ValueError("encryptedData has no OpenSSL Salted__ header")

    salt = raw[8:16]
    ciphertext = raw[16:]
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("encryptedData has an invalid AES block length")

    key, iv = _evp_bytes_to_key(master_password, salt)
    plaintext = _aes256_cbc_decrypt(ciphertext, key, iv)
    try:
        decoded = plaintext.decode("utf-8")
        parsed = json.loads(decoded)
    except Exception as ex:
        raise ValueError("decrypted backup is not valid UTF-8 JSON") from ex
    if not isinstance(parsed, dict):
        raise ValueError("decrypted backup root is not a JSON object")
    return parsed, hashlib.sha256(plaintext).hexdigest()


def _backup_from_redux_value(value):
    root = _safe_json_loads(value)
    if not isinstance(root, dict):
        return None
    raw_backup = root.get("backup")
    decoded_backup = _safe_json_loads(raw_backup)
    return raw_backup if decoded_backup is None else decoded_backup


def _read_backup_objects_from_rkstorage(path):
    backups = []
    seen = set()
    try:
        _, records = _read_rkstorage_records(path)
        for table, key, value in records:
            decoded = _safe_json_loads(value)
            candidates = []
            if str(key).lower() == "backup" and isinstance(decoded, dict):
                candidates.append((f"{table}.{key}", decoded))
            candidates.extend(_find_backup_objects(value))
            for location, backup in candidates:
                if not isinstance(backup, dict):
                    continue
                marker = _sha256_text(json.dumps(backup, ensure_ascii=False, sort_keys=True, default=str))
                if marker in seen:
                    continue
                seen.add(marker)
                backups.append((f"{table}.{key}:{location}", backup))
    except Exception:
        return []
    return backups


def _collect_master_password_candidates(files_found):
    """Collect internal keys and bind each one to its encrypted blob hash."""
    candidates = []
    seen = set()
    for file_found in files_found:
        path = str(file_found)
        name = pathlib.Path(path).name
        if not os.path.isfile(path):
            continue
        if name == "RKStorage":
            backup_objects = _read_backup_objects_from_rkstorage(path)
        elif name.lower().endswith(".json") and "rkstorage" in name.lower():
            try:
                raw = pathlib.Path(path).read_text(encoding="utf-8-sig", errors="replace")
                backup_objects = _find_backup_objects(raw)
            except Exception:
                backup_objects = []
        else:
            continue
        for location, backup in backup_objects:
            master_password = backup.get("masterPassword")
            encrypted = backup.get("encryptedData")
            if not isinstance(master_password, str) or not master_password:
                continue
            encrypted_sha = _sha256_text(encrypted) if encrypted else ""
            secret_sha = _sha256_text(master_password)
            marker = (secret_sha, encrypted_sha)
            if marker in seen:
                continue
            seen.add(marker)
            candidates.append({
                "master_password": master_password,
                "encrypted_sha256": encrypted_sha,
                "source": f"{path} [{location}]",
            })
    return candidates


def _ms_to_utc(value):
    try:
        ivalue = int(value)
        if ivalue > 10**12:
            dt = datetime.datetime.fromtimestamp(ivalue / 1000, datetime.timezone.utc)
            return dt.isoformat()
        if ivalue > 10**9:
            dt = datetime.datetime.fromtimestamp(ivalue, datetime.timezone.utc)
            return dt.isoformat()
    except Exception:
        return ""
    return ""


def _is_sensitive_key(key):
    k = str(key or "").replace("-", "").replace("_", "").lower()
    # Be strict here to avoid marking derivedFromMnemonicUsing as the mnemonic itself.
    exact_sensitive = {"privatekey", "private", "seed", "mnemonic", "password", "masterpassword",
                       "spendkey", "stakekey", "wif", "xprv", "secret", "encrypteddata"}
    return k in exact_sensitive or k.endswith("privatekey") or k.endswith("spendkey") or k.endswith("stakekey")


def _extract_ascii_strings(data, min_len=8):
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    for raw in re.findall(pattern, data or b""):
        yield raw.decode("utf-8", errors="replace")


def _classify_address(value, fallback_family=""):
    v = str(value or "")
    f = str(fallback_family or "").lower()
    if EVM_RE.fullmatch(v):
        return "Ethereum/EVM-style address"
    if BNB_RE.fullmatch(v):
        return "BNB Beacon Chain bech32 address"
    if ADA_RE.fullmatch(v):
        return "Cardano bech32 address"
    if TRON_RE.fullmatch(v):
        return "TRON base58 address"
    if XRP_RE.fullmatch(v):
        return "XRP classic address"
    if DOGE_RE.fullmatch(v):
        return "Dogecoin address"
    if BTC_RE.fullmatch(v):
        if f in ("doge", "dogecoin"):
            return "Dogecoin-like address"
        return "Bitcoin-style address"
    return f"Public address for {fallback_family}" if fallback_family else "Public address"


def _find_addresses_in_text(text):
    rows = []
    seen = set()
    text = text or ""
    for label, regex in ADDRESS_REGEXES:
        for m in regex.finditer(text):
            address = m.group(0)
            key = (label, address)
            if key in seen:
                continue
            seen.add(key)
            rows.append((label, address))
    return rows


def _row(kind, name, asset, value, balance, notes, source):
    return (str(kind or ""), str(name or ""), str(asset or ""), str(value or ""), str(balance or ""), str(notes or ""), str(source or ""))


def _validate_bip39_english(mnemonic):
    """Validate BIP-39 English word membership and checksum without network access."""
    normalized = unicodedata.normalize("NFKD", str(mnemonic or "")).strip().lower()
    words = normalized.split()
    result = {
        "word_count": len(words),
        "valid_length": len(words) in {12, 15, 18, 21, 24},
        "unknown_words": [],
        "words_valid": False,
        "checksum_valid": False,
        "valid": False,
        "status": "Invalid BIP-39 mnemonic",
    }
    result["unknown_words"] = [word for word in words if word not in BIP39_ENGLISH_INDEX]
    result["words_valid"] = not result["unknown_words"]

    if not result["valid_length"]:
        result["status"] = f"Invalid BIP-39 word count ({len(words)})"
        return result
    if not result["words_valid"]:
        result["status"] = "Invalid BIP-39 English word list"
        return result

    bits = "".join(f"{BIP39_ENGLISH_INDEX[word]:011b}" for word in words)
    entropy_length = (len(bits) * 32) // 33
    checksum_length = len(bits) - entropy_length
    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[entropy_length:]
    entropy = int(entropy_bits, 2).to_bytes(entropy_length // 8, "big")
    expected_checksum = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())[:checksum_length]
    result["checksum_valid"] = checksum_bits == expected_checksum
    result["valid"] = result["checksum_valid"]
    result["status"] = "Valid BIP-39 English mnemonic" if result["valid"] else "Invalid BIP-39 checksum"
    return result


def _mnemonic_validation_notes(validation):
    unknown = validation.get("unknown_words") or []
    unknown_note = f"; unknown_words={', '.join(unknown)}" if unknown else ""
    return (
        f"word_count={validation.get('word_count')}; "
        f"valid_length={validation.get('valid_length')}; "
        f"all_words_in_english_list={validation.get('words_valid')}; "
        f"checksum_valid={validation.get('checksum_valid')}"
        f"{unknown_note}"
    )


def _parse_private_key_value(private_value, wallet_uuid, asset, source):
    rows = []
    if isinstance(private_value, dict):
        for key_name, key_value in private_value.items():
            rows.append(_row(
                "Private Key", wallet_uuid, f"{asset} / {key_name}", key_value, "",
                "Recovered from wallet.privateKey object", source,
            ))
            if str(key_name).lower() == "mnemonic":
                validation = _validate_bip39_english(key_value)
                rows.append(_row(
                    "Mnemonic Validation", wallet_uuid, f"{asset} / privateKey.mnemonic",
                    validation["status"], "", _mnemonic_validation_notes(validation), source,
                ))
    elif private_value not in (None, ""):
        rows.append(_row(
            "Private Key", wallet_uuid, asset, private_value, "",
            "Recovered from wallet.privateKey", source,
        ))
    return rows


def _parse_wallet_entry(wallet, source, parent_uuid="", is_token=False):
    rows = []
    if not isinstance(wallet, dict):
        return rows

    uuid = wallet.get("uuid", "")
    currency = wallet.get("currency") or wallet.get("family") or ""
    title = wallet.get("title", "")
    family = wallet.get("family", "")
    asset = f"{currency}"
    if title and title.lower() != str(currency).lower():
        asset = f"{currency} - {title}"
    if family and family != currency:
        asset += f" / family={family}"

    address = wallet.get("address", "")
    balance = wallet.get("balance", "")
    notes = _classify_address(address, family or currency) if address else "No public address stored"
    if parent_uuid:
        notes += f"; parentUuid={parent_uuid}"
    if wallet.get("derivedFromMnemonicUsing"):
        notes += f"; derivedFromMnemonicUsing={wallet.get('derivedFromMnemonicUsing')}"
    kind = "Token/SubWallet" if is_token else "Wallet Account"
    rows.append(_row(kind, uuid, asset, address, balance, notes, source))

    identity = (
        f"currency={currency}; title={title}; family={family}; "
        f"derivedFromMnemonicUsing={wallet.get('derivedFromMnemonicUsing', '')}; "
        f"parentUuid={parent_uuid}"
    )
    rows.append(_row("Wallet Identifier", uuid, asset, identity, "", "Wallet identification and derivation metadata", source))

    rows.extend(_parse_private_key_value(wallet.get("privateKey"), uuid, asset, source))
    if "mnemonic" in wallet:
        wallet_mnemonic = wallet.get("mnemonic")
        validation = _validate_bip39_english(wallet_mnemonic)
        rows.append(_row("Mnemonic", uuid, asset, wallet_mnemonic, "", "Mnemonic stored inside wallet object", source))
        rows.append(_row(
            "Mnemonic Validation", uuid, asset, validation["status"], "",
            _mnemonic_validation_notes(validation), source,
        ))

    smart_contract = wallet.get("smartContract") or wallet.get("contract")
    if smart_contract:
        notes = "Token/smart contract identifier"
        if EVM_RE.fullmatch(str(smart_contract)):
            notes = "EVM token contract address"
        elif TRON_RE.fullmatch(str(smart_contract)):
            notes = "TRON token contract address"
        rows.append(_row("Token Contract", uuid, asset, smart_contract, "", notes, source))

    subwallets = wallet.get("subWallets") or []
    if isinstance(subwallets, list):
        for sub in subwallets:
            rows.extend(_parse_wallet_entry(sub, source, parent_uuid=uuid, is_token=True))

    return rows

def _parse_backup_data(data, source, provenance):
    rows = []
    if not isinstance(data, dict):
        return rows

    version = data.get("version", "")
    backup_uuid = data.get("uuid", "")
    last_update = data.get("last-update-time", "")
    dt = _ms_to_utc(last_update)
    rows.append(_row(
        "Backup Metadata", provenance, "", f"version={version}; uuid={backup_uuid}", "",
        f"last-update-time={last_update}; utc={dt}", source,
    ))

    if "mnemonic" in data:
        mnemonic = data.get("mnemonic")
        validation = _validate_bip39_english(mnemonic)
        rows.append(_row(
            "Mnemonic", "backup.mnemonic", provenance, mnemonic, "",
            "Recovered wallet mnemonic", source,
        ))
        rows.append(_row(
            "Mnemonic Validation", "backup.mnemonic", provenance, validation["status"], "",
            _mnemonic_validation_notes(validation), source,
        ))

    if "autobackup-setting" in data:
        rows.append(_row(
            "Backup Metadata", "autobackup-setting", provenance,
            data.get("autobackup-setting"), "", "Backup configuration value", source,
        ))

    wallets = data.get("walletsByUuids")
    wallet_label = "walletsByUuids"
    if not isinstance(wallets, (dict, list)):
        wallets = data.get("wallets")
        wallet_label = "wallets"

    if isinstance(wallets, dict):
        wallet_values = list(wallets.values())
    elif isinstance(wallets, list):
        wallet_values = wallets
    else:
        wallet_values = []

    rows.append(_row(
        "Wallet Summary", wallet_label, "", str(len(wallet_values)), "",
        f"Number of top-level wallets in {provenance}; all recovered fields are reported", source,
    ))
    for wallet in wallet_values:
        rows.extend(_parse_wallet_entry(wallet, source))

    return rows


def _parse_backup_object(backup_obj, source, master_password_candidates=None):
    rows = []
    if not isinstance(backup_obj, dict):
        return rows

    master_password_candidates = master_password_candidates or []
    btype = backup_obj.get("type", "")
    rows.append(_row("Backup Metadata", "backup.type", "", btype, "", "Redux backup object found in RKStorage", source))

    encrypted = backup_obj.get("encryptedData")
    encrypted_sha = ""
    if encrypted:
        encrypted_sha = _sha256_text(encrypted)
        rows.append(_row(
            "Encrypted Backup", "encryptedData", "OpenSSL/CryptoJS Salted__ Base64", "Present", "",
            f"length={len(str(encrypted))}; sha256={encrypted_sha}; raw ciphertext omitted from the report to keep it readable", source,
        ))

    local_master_password = backup_obj.get("masterPassword")
    if "masterPassword" in backup_obj:
        rows.append(_row(
            "Internal Decryption Key", "masterPassword", "Guarda backup credential", local_master_password, "",
            f"SENSITIVE WALLET EVIDENCE - full recovered internal masterPassword; length={len(str(local_master_password or ''))}", source,
        ))

    data = backup_obj.get("data")
    if isinstance(data, dict):
        rows.extend(_parse_backup_data(data, source, "backup.data (plaintext state)"))

    if not encrypted:
        return rows

    keys_to_try = []
    if isinstance(local_master_password, str) and local_master_password:
        keys_to_try.append((local_master_password, source, "same RKStorage"))

    for candidate in master_password_candidates:
        if candidate.get("encrypted_sha256") != encrypted_sha:
            continue
        candidate_password = candidate.get("master_password")
        if not isinstance(candidate_password, str) or not candidate_password:
            continue
        if any(existing[0] == candidate_password for existing in keys_to_try):
            continue
        keys_to_try.append((candidate_password, candidate.get("source", ""), "matching acquisition"))

    if not keys_to_try:
        rows.append(_row(
            "Backup Decryption", "encryptedData", "OpenSSL/CryptoJS AES-256-CBC", "Not decrypted", "",
            "Internal backup.masterPassword was not recovered in this evidence set; the user's unlock password is not assumed to be equivalent", source,
        ))
        return rows

    errors = []
    for master_password, key_source, _key_scope in keys_to_try:
        try:
            decrypted, plaintext_sha = _decrypt_cryptojs_backup(encrypted, master_password)
            key_source_note = "same RKStorage" if key_source == source else f"matching RKStorage source={key_source}"
            rows.append(_row(
                "Backup Decryption", "encryptedData", "OpenSSL/CryptoJS AES-256-CBC", "Successful", "",
                "Decrypted in memory with internal backup.masterPassword from "
                f"{key_source_note}; EVP_BytesToKey-compatible MD5 derivation; plaintext_sha256={plaintext_sha}; "
                "all recovered JSON values are included in the detailed forensic report", source,
            ))
            rows.extend(_parse_backup_data(decrypted, source, "decrypted encryptedData"))
            return rows
        except Exception as ex:
            errors.append(type(ex).__name__)

    rows.append(_row(
        "Backup Decryption", "encryptedData", "OpenSSL/CryptoJS AES-256-CBC", "Failed", "",
        f"Tried {len(keys_to_try)} internal masterPassword candidate(s); error_types={', '.join(sorted(set(errors)))}; no plaintext written", source,
    ))
    return rows


def _parse_redux_root(value, source, master_password_candidates=None, record_name="persist:root"):
    rows = []
    root = _safe_json_loads(value)
    if not isinstance(root, dict):
        rows.append(_row("RKStorage", record_name, "", "<not parsed>", "", "Value is not valid JSON", source))
        return rows

    rows.append(_row("RKStorage Summary", record_name, "", f"top_keys={', '.join(str(k) for k in root.keys())}", "", f"json_length={len(str(value))}; sha256={_sha256_text(value)}", source))

    # Parse app settings and skip large supported-token catalogues as noise.
    skip_top_keys = {"buySupportedTokens", "exchangeSupportedTokens"}
    for top_key, raw in root.items():
        if top_key in skip_top_keys:
            obj = _safe_json_loads(raw)
            if isinstance(obj, dict):
                coins = obj.get("coins") or []
                rows.append(_row("Catalog Summary", top_key, "", f"coins={len(coins)}", "", "Large token support catalogue skipped to reduce irrelevant records", source))
            continue

        obj = _safe_json_loads(raw) if isinstance(raw, str) else raw
        if top_key == "backup":
            rows.extend(_parse_backup_object(obj, source, master_password_candidates))
        elif top_key == "settings" and isinstance(obj, dict):
            for k, v in obj.items():
                if _is_sensitive_key(k):
                    rows.append(_row("Sensitive State Value", k, "Redux setting", v, "", "SENSITIVE EVIDENCE - full value", source))
                else:
                    rows.append(_row("Setting", k, "", v, "", "App setting from Redux state", source))
        elif top_key == "balanceLoading" and isinstance(obj, dict):
            wallets = obj.get("wallets") or {}
            if isinstance(wallets, dict):
                non_zero = []
                for uuid, info in wallets.items():
                    bal = str((info or {}).get("balance", "")) if isinstance(info, dict) else ""
                    if bal not in ("", "0", "0.0", "0.00"):
                        non_zero.append((uuid, bal))
                rows.append(_row("Balance Summary", "balanceLoading.wallets", "", f"wallet_count={len(wallets)}", "", f"non_zero={len(non_zero)}", source))
                for uuid, bal in non_zero:
                    rows.append(_row("Balance", uuid, "", "", bal, "Non-zero visible balance from balanceLoading", source))
        elif top_key == "walletConnect" and isinstance(obj, dict):
            rows.append(_row("WalletConnect", "status", "", obj.get("status", ""), "", f"initiatedSessions={len(obj.get('initiatedSessions') or [])}; requests={len(obj.get('requests') or [])}", source))
        elif top_key == "_persist" and isinstance(obj, dict):
            rows.append(_row("Redux Persist", "_persist", "", f"version={obj.get('version')}; rehydrated={obj.get('rehydrated')}", "", "Redux persistence metadata", source))
        elif top_key in ("banners", "biometryAuthProposal", "cordovaBackupDecoder", "hiddenWallets", "walletsScreen") and isinstance(obj, dict):
            # Keep compact summaries only.
            compact = json.dumps(obj, ensure_ascii=False, sort_keys=True)
            if len(compact) > 500:
                compact = compact[:500] + "..."
            rows.append(_row("State Summary", top_key, "", compact, "", "Compact Redux state summary", source))

    return rows


def _parse_rkstorage(path, master_password_candidates=None):
    rows = []
    p = pathlib.Path(path)
    rows.append(_row("File Metadata", p.name, "SQLite/RKStorage", f"{_safe_size(path)} bytes", "", f"sha256={_sha256_file(path)}", path))
    try:
        table_info, records = _read_rkstorage_records(path)
        table_names = [table for table, _columns, _count in table_info]
        rows.append(_row(
            "SQLite Metadata", p.name, "", ", ".join(table_names) or "<no user tables>", "",
            "SQLite tables; opened read-only; schema-independent scan enabled", path,
        ))
        for table, columns, row_count in table_info:
            rows.append(_row(
                "RKStorage Diagnostic", table, "SQLite table", f"rows={row_count}", "",
                f"columns={', '.join(columns) or '<none>'}", path,
            ))

        json_record_count = 0
        redux_state_count = 0
        backup_object_count = 0
        seen_backups = set()
        redux_markers = {"backup", "settings", "balanceloading", "_persist", "walletsscreen"}

        for table, key, value in records:
            decoded = _safe_json_loads(value)
            record_name = f"{table}.{key}"
            record_source = f"{path} [{record_name}]"
            if decoded is not None:
                json_record_count += 1

            if isinstance(decoded, dict):
                lowered_keys = {str(item).lower() for item in decoded.keys()}
                if lowered_keys & redux_markers:
                    rows.extend(_parse_redux_root(
                        decoded, record_source, master_password_candidates, record_name=record_name
                    ))
                    redux_state_count += 1
                    raw_backup = decoded.get("backup")
                    if isinstance(raw_backup, dict):
                        seen_backups.add(_sha256_text(json.dumps(
                            raw_backup, ensure_ascii=False, sort_keys=True, default=str
                        )))

            backup_candidates = []
            if str(key).lower() == "backup" and isinstance(decoded, dict):
                backup_candidates.append(("root", decoded))
            backup_candidates.extend(_find_backup_objects(value))
            for location, backup in backup_candidates:
                if not isinstance(backup, dict):
                    continue
                marker = _sha256_text(json.dumps(backup, ensure_ascii=False, sort_keys=True, default=str))
                if marker in seen_backups:
                    continue
                seen_backups.add(marker)
                backup_object_count += 1
                rows.extend(_parse_backup_object(
                    backup, f"{record_source}::{location}", master_password_candidates
                ))

            if decoded is None and _is_sensitive_key(key):
                rows.append(_row(
                    "Sensitive AsyncStorage Value", record_name, "", value, "",
                    "SENSITIVE EVIDENCE - full non-JSON value", record_source,
                ))

        parsed_backup_rows = [
            row for row in rows if row[0] == "Backup Metadata" and row[1] == "backup.type"
        ]
        detected_backup_count = len({row[6] for row in parsed_backup_rows})
        backup_object_count = max(backup_object_count, detected_backup_count)
        rows.append(_row(
            "RKStorage Diagnostic", "scan summary", "Automatic schema scan",
            f"tables={len(table_info)}; candidate_records={len(records)}; json_records={json_record_count}; "
            f"redux_states={redux_state_count}; backup_objects={backup_object_count}", "",
            "Every key/value pair and every TEXT/BLOB column was inspected recursively", path,
        ))
        if backup_object_count == 0:
            rows.append(_row(
                "RKStorage Diagnostic", "backup detection", "Automatic schema scan", "NOT FOUND", "",
                "RKStorage opened successfully, but no object containing backup, encryptedData or masterPassword was found; "
                "review the table/column diagnostics in this report", path,
            ))
    except Exception as ex:
        rows.append(_row(
            "Parse Error", p.name, "SQLite/RKStorage", f"{type(ex).__name__}: {ex}", "",
            "RKStorage could not be opened or scanned; verify the source is the SQLite database, not a journal/WAL", path,
        ))
    return rows


def _parse_rkstorage_json(path, master_password_candidates=None):
    """Parse a JSON export/dump of RKStorage using the same recursive detection."""
    rows = []
    p = pathlib.Path(path)
    rows.append(_row(
        "File Metadata", p.name, "RKStorage JSON export", f"{_safe_size(path)} bytes", "",
        f"sha256={_sha256_file(path)}", path,
    ))
    try:
        raw = p.read_text(encoding="utf-8-sig", errors="replace")
        decoded = _safe_json_loads(raw)
        if decoded is None:
            raise ValueError("file does not contain valid JSON")

        root_keys = {str(key).lower() for key in decoded.keys()} if isinstance(decoded, dict) else set()
        if root_keys & {"backup", "settings", "balanceloading", "_persist", "walletsscreen"}:
            rows.extend(_parse_redux_root(decoded, path, master_password_candidates, record_name=p.name))

        seen = set()
        root_backup_marker = None
        if isinstance(decoded, dict) and isinstance(decoded.get("backup"), dict):
            root_backup_marker = _sha256_text(json.dumps(
                decoded["backup"], ensure_ascii=False, sort_keys=True, default=str
            ))
        for location, backup in _find_backup_objects(decoded):
            marker = _sha256_text(json.dumps(backup, ensure_ascii=False, sort_keys=True, default=str))
            if marker in seen:
                continue
            seen.add(marker)
            if marker == root_backup_marker:
                continue
            rows.extend(_parse_backup_object(backup, f"{path}::{location}", master_password_candidates))

        parsed = any(row[0] == "Backup Metadata" for row in rows)
        rows.append(_row(
            "RKStorage Diagnostic", "JSON scan summary", "Recursive JSON scan",
            f"backup_objects={len(seen)}; parsed={'yes' if parsed else 'no'}", "",
            "Nested and JSON-encoded strings were decoded recursively", path,
        ))
        if not parsed:
            rows.append(_row(
                "RKStorage Diagnostic", "backup detection", "Recursive JSON scan", "NOT FOUND", "",
                "No backup/encryptedData/masterPassword object was found in this JSON export", path,
            ))
    except Exception as ex:
        rows.append(_row(
            "Parse Error", p.name, "RKStorage JSON export", f"{type(ex).__name__}: {ex}", "",
            "Failed to parse JSON export", path,
        ))
    return rows


def _parse_xml_prefs(path):
    rows = []
    p = pathlib.Path(path)
    rows.append(_row("File Metadata", p.name, "SharedPreferences", f"{_safe_size(path)} bytes", "", f"sha256={_sha256_file(path)}", path))
    try:
        root = ET.parse(path).getroot()
    except Exception as ex:
        return rows + [_row("Parse Error", p.name, "SharedPreferences", str(ex), "", "XML parse failed", path)]

    for elem in root:
        name = elem.attrib.get("name", "")
        if elem.tag == "string":
            value = elem.text or ""
        elif elem.tag == "set":
            value = "; ".join([child.text or "" for child in elem])
        else:
            value = elem.attrib.get("value", "")
        if _is_sensitive_key(name):
            rows.append(_row("Sensitive Shared Preference", name, p.name, value, "", "SENSITIVE EVIDENCE - full value", path))
        else:
            notes = elem.tag
            dt = _ms_to_utc(value)
            if dt:
                notes += f"; utc={dt}"
            rows.append(_row("Shared Preference", name, p.name, value, "", notes, path))
    return rows


def _parse_backup_file(path):
    rows = []
    p = pathlib.Path(path)
    size = _safe_size(path)
    sha = _sha256_file(path)
    rows.append(_row("Backup File", p.name, "Encrypted wallet backup", "See complete value below", "", f"size={size} bytes; sha256={sha}", path))
    try:
        text = p.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("U2FsdGVkX1"):
            rows.append(_row(
                "Encrypted Backup", p.name, "OpenSSL/CryptoJS salted blob", "Present", "",
                f"length={len(text)}; sha256={_sha256_text(text)}; raw ciphertext omitted from the report", path,
            ))
        else:
            # Only scan for public addresses if it is not an encrypted backup blob.
            for label, addr in _find_addresses_in_text(text):
                rows.append(_row("Address Candidate", p.name, label, addr, "", "Found in backup file text scan", path))
    except Exception as ex:
        rows.append(_row("Parse Error", p.name, "Backup file", str(ex), "", "Failed reading backup file", path))
    return rows


def _parse_cookies(path):
    rows = []
    p = pathlib.Path(path)
    rows.append(_row("File Metadata", p.name, "WebView Cookies", f"{_safe_size(path)} bytes", "", f"sha256={_sha256_file(path)}", path))
    try:
        with _open_sqlite_readonly(path) as con:
            cur = con.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if "cookies" not in tables:
                return rows
            sql = "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, value, encrypted_value FROM cookies"
            for host, name, cpath, expires, secure, httponly, cookie_value, encrypted_value in cur.execute(sql).fetchall():
                # Guarda domains are useful. Skip general Google/Firebase cookies if ever present.
                if "guarda.com" not in str(host).lower():
                    continue
                note = f"path={cpath}; expires_utc_chrome={expires}; secure={secure}; httponly={httponly}"
                rows.append(_row("Sensitive WebView Cookie", name, host, cookie_value or "", "", f"SENSITIVE EVIDENCE - plaintext cookie value; {note}", path))
                if encrypted_value:
                    if isinstance(encrypted_value, str):
                        encoded_value = encrypted_value
                    else:
                        encoded_value = base64.b64encode(bytes(encrypted_value)).decode("ascii")
                    rows.append(_row("Sensitive WebView Cookie", f"{name}.encrypted_value", host, encoded_value, "", f"SENSITIVE EVIDENCE - encrypted cookie bytes as Base64; {note}", path))
    except Exception as ex:
        rows.append(_row("Parse Error", p.name, "WebView Cookies", str(ex), "", "Failed to parse Cookies SQLite DB", path))
    return rows


def _parse_mmkv_or_binary(path):
    rows = []
    p = pathlib.Path(path)
    size = _safe_size(path)
    rows.append(_row("File Metadata", p.name, "MMKV/Binary", f"{size} bytes", "", f"sha256={_sha256_file(path)}", path))
    rows.append(_row("Scan Note", p.name, "MMKV/Binary", "not string-dumped", "", "MMKV can contain noisy binary/repeated data; plugin keeps metadata only to avoid irrelevant/duplicate records", path))
    return rows

def _parse_leveldb_log(path):
    rows = []
    p = pathlib.Path(path)
    # These logs are usually tiny; only output metadata and any public address candidates.
    try:
        data = p.read_bytes()
        text = "\n".join(_extract_ascii_strings(data, 8))
        found = _find_addresses_in_text(text)
        if not found:
            return []  # remove irrelevant empty/noise LevelDB log files
        rows.append(_row("File Metadata", p.name, "WebView Local Storage LevelDB", f"{_safe_size(path)} bytes", "", f"sha256={_sha256_file(path)}", path))
        for label, addr in found:
            rows.append(_row("Address Candidate", p.name, label, addr, "", "Found in WebView LevelDB log string scan", path))
    except Exception as ex:
        rows.append(_row("Parse Error", p.name, "LevelDB log", str(ex), "", "LevelDB log scan failed", path))
    return rows


def _should_skip_file(path):
    sp = _safe_rel(path)
    name = pathlib.Path(path).name
    if name.endswith("-journal") or name in {"LOCK", "LOG", "LOG.old", "CURRENT", "MANIFEST-000019", "MANIFEST-000002"}:
        return True
    if name.startswith("com.google") or "firebase" in name.lower() or "FirebaseHeartBeat" in name:
        return True
    return False


def _parse_file(path, master_password_candidates=None):
    p = pathlib.Path(path)
    name = p.name
    sp = _safe_rel(path).lower()
    if name == "RKStorage":
        return _parse_rkstorage(path, master_password_candidates)
    if name.lower().endswith(".json") and "rkstorage" in name.lower():
        return _parse_rkstorage_json(path, master_password_candidates)
    if name.lower().startswith("backup") or "backup" in name.lower():
        return _parse_backup_file(path)
    if name == "Cookies":
        return _parse_cookies(path)
    if name == "mmkv.default" or name == "mmkv.default.crc":
        return _parse_mmkv_or_binary(path)
    if name.endswith(".xml"):
        return _parse_xml_prefs(path)
    if "local storage/leveldb" in sp and name.endswith(".log"):
        return _parse_leveldb_log(path)
    return []


def _compact_join(items, limit=6):
    clean = [str(x) for x in items if str(x)]
    if not clean:
        return ""
    shown = clean[:limit]
    suffix = f"; +{len(clean) - limit} more" if len(clean) > limit else ""
    return "; ".join(shown) + suffix


def _is_non_zero_balance(balance):
    try:
        return float(str(balance).replace(",", ".")) != 0.0
    except Exception:
        return str(balance).strip() not in ("", "0", "0.0", "0.00")


def _build_guarda_summary(rows, processed_sources, skipped_duplicates=0):
    wallet_rows = [r for r in rows if r[0] == "Wallet Account"]
    token_rows = [r for r in rows if r[0] == "Token/SubWallet"]
    contract_rows = [r for r in rows if r[0] == "Token Contract"]
    backup_rows = [r for r in rows if r[0] in {"Backup File", "Backup Metadata"}]
    mnemonic_rows = [r for r in rows if r[0] == "Mnemonic"]
    mnemonic_validation_rows = [r for r in rows if r[0] == "Mnemonic Validation"]
    private_key_rows = [r for r in rows if r[0] == "Private Key"]
    master_key_rows = [r for r in rows if r[0] == "Internal Decryption Key"]
    decryption_rows = [r for r in rows if r[0] == "Backup Decryption"]
    decryption_successes = [r for r in decryption_rows if r[3] == "Successful"]

    unique_addresses = []
    seen_addr = set()
    for r in wallet_rows + token_rows:
        addr = r[3]
        if addr and addr not in seen_addr and addr != "<REDACTED>":
            seen_addr.add(addr)
            unique_addresses.append(addr)

    wallet_ids = [f"{r[2].split(' / ')[0]}:{r[1]}" for r in wallet_rows]
    wallet_addresses = [f"{r[2].split(' / ')[0]}={r[3]}" for r in wallet_rows]
    non_zero_wallets = [
        f"{r[2].split(' / ')[0]} {r[1]} balance={r[4]} address={r[3]}"
        for r in wallet_rows
        if _is_non_zero_balance(r[4])
    ]
    source_names = sorted({pathlib.Path(s).name for s in processed_sources if s})
    rkstorage_seen = any(pathlib.Path(s).name == "RKStorage" for s in processed_sources)

    summary = [
        _row("00. Executive Summary", "Application", "Guarda Crypto Wallet / Crypto Multiwallet", APP_PACKAGE, "", "Target Android package analysed by this ALEAPP plugin", ""),
        _row("00. Executive Summary", "Main evidence store", "React Native AsyncStorage", "databases/RKStorage" if rkstorage_seen else "RKStorage not found", "", "Primary store parsed for persisted Redux state and wallet metadata", ""),
        _row("00. Executive Summary", "Wallet accounts", "Top-level wallets", str(len(wallet_rows)), "", f"Wallet UUIDs: {_compact_join(wallet_ids, 12)}", ""),
        _row("00. Executive Summary", "Public wallet addresses", "Top-level wallet addresses", str(len(unique_addresses)), "", _compact_join(wallet_addresses, 8), ""),
        _row("00. Executive Summary", "Token/SubWallet entries", "Tokens and child wallets", str(len(token_rows)), "", f"Token contracts found={len(contract_rows)}", ""),
        _row("00. Executive Summary", "Non-zero visible balances", "Balance triage", str(len(non_zero_wallets)), "", _compact_join(non_zero_wallets, 4) if non_zero_wallets else "No non-zero top-level wallet balance visible in parsed state", ""),
        _row("00. Executive Summary", "Backup artefact", "Encrypted backup", "Present" if backup_rows else "Not found", "", "Complete encrypted and decrypted values are included in the detailed report" if backup_rows else "No backup file/object identified", ""),
        _row("00. Executive Summary", "Backup decryption", "Full forensic processing", "Successful" if decryption_successes else "Not completed", "", f"successful_sources={len(decryption_successes)}; all recovered JSON values are reported", ""),
        _row("00. Executive Summary", "Sensitive evidence", "WARNING", str(len(mnemonic_rows) + len(private_key_rows) + len(master_key_rows)), "", "Report contains recovered mnemonic/privateKey/masterPassword values; raw encryptedData is represented only by length and SHA-256", ""),
        _row("00. Executive Summary", "Noise reduction", "Deduplication/filtering", f"processed_sources={len(processed_sources)}", "", f"duplicate_files_skipped={skipped_duplicates}; Google/Firebase/cache/journal artefacts ignored where possible", ""),
        _row("00. Executive Summary", "Relevant source files", "Evidence files", _compact_join(source_names, 10), "", "Use this block for report screenshots before the detailed rows", ""),
    ]

    # Put the most useful wallet-address rows immediately after the summary for report screenshots.
    if wallet_rows:
        summary.append(_row("01. Wallet Address Overview", "Wallet IDs and public addresses", "Guarda top-level wallets", str(len(wallet_rows)), "", "The detailed wallet rows below list UUID, asset, public address and visible balance.", ""))
        for r in wallet_rows:
            summary.append(_row("01. Wallet Address Overview", r[1], r[2], r[3], r[4], r[5], r[6]))

    return summary




def _explorer_url(asset, address):
    asset_upper = str(asset or "").split(" - ")[0].split(" / ")[0].strip().upper()
    addr = str(address or "").strip()
    if not addr or addr == "<REDACTED>":
        return ""

    if asset_upper == "ETH":
        return f"https://etherscan.io/address/{addr}"
    if asset_upper == "BSC":
        return f"https://bscscan.com/address/{addr}"
    if asset_upper in {"MATIC", "POL", "POLYGON"}:
        return f"https://polygonscan.com/address/{addr}"
    if asset_upper == "BTC":
        return f"https://www.blockchain.com/explorer/addresses/btc/{addr}"
    if asset_upper == "ADA":
        return f"https://cardanoscan.io/address/{addr}"
    if asset_upper == "DOGE":
        return f"https://dogechain.info/address/{addr}"
    if asset_upper == "XRP":
        return f"https://xrpscan.com/account/{addr}"
    if asset_upper == "TRX":
        return f"https://tronscan.org/#/address/{addr}"
    if asset_upper == "BNB":
        return f"https://explorer.bnbchain.org/address/{addr}"
    if EVM_RE.fullmatch(addr):
        return f"https://etherscan.io/address/{addr}"
    return ""


def _html_link(label, url):
    label = html.escape(str(label or ""))
    url = html.escape(str(url or ""), quote=True)
    if not url:
        return label
    return f'<a href="{url}" target="_blank">{label}</a>'


def _build_guarda_top_html(rows, processed_sources, skipped_duplicates=0):
    def unique_rows(items, key_indexes):
        output = []
        seen = set()
        for item in items:
            marker = tuple(item[index] for index in key_indexes)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
        return output

    # The same wallet can exist in plaintext backup.data and in the decrypted
    # encryptedData, or in two acquisitions. Keep every provenance row in the
    # detailed table, but count/display each logical wallet once in the summary.
    wallet_rows = unique_rows([r for r in rows if r[0] == "Wallet Account"], (1, 2, 3, 4))
    token_rows = unique_rows([r for r in rows if r[0] == "Token/SubWallet"], (1, 2, 3, 4))
    contract_rows = [r for r in rows if r[0] == "Token Contract"]
    backup_rows = [r for r in rows if r[0] in {"Backup File", "Backup Metadata"}]
    mnemonic_rows = [r for r in rows if r[0] == "Mnemonic"]
    mnemonic_validation_rows = [r for r in rows if r[0] == "Mnemonic Validation"]
    private_key_rows = unique_rows([r for r in rows if r[0] == "Private Key"], (1, 2, 3))
    master_key_rows = [r for r in rows if r[0] == "Internal Decryption Key"]
    decryption_rows = [r for r in rows if r[0] == "Backup Decryption"]
    decryption_successes = [r for r in decryption_rows if r[3] == "Successful"]
    diagnostic_rows = [r for r in rows if r[0] == "RKStorage Diagnostic"]
    scan_summary_rows = [r for r in diagnostic_rows if r[1] in {"scan summary", "JSON scan summary"}]
    backup_not_found_rows = [r for r in diagnostic_rows if r[1] == "backup detection" and r[3] == "NOT FOUND"]
    parse_error_rows = [r for r in rows if r[0] == "Parse Error" and "RKStorage" in r[2]]

    unique_addresses = []
    seen_addr = set()
    for r in wallet_rows:
        addr = r[3]
        if addr and addr != "<REDACTED>" and addr not in seen_addr:
            seen_addr.add(addr)
            unique_addresses.append(addr)

    non_zero_wallets = [r for r in wallet_rows if _is_non_zero_balance(r[4])]
    source_names = sorted({pathlib.Path(s).name for s in processed_sources if s})

    private_keys_by_uuid = {}
    for private_row in private_key_rows:
        private_keys_by_uuid.setdefault(private_row[1], [])
        key_item = (private_row[2], private_row[3])
        if key_item not in private_keys_by_uuid[private_row[1]]:
            private_keys_by_uuid[private_row[1]].append(key_item)

    wallet_table_rows = []
    all_wallet_rows = wallet_rows + token_rows
    for idx, r in enumerate(all_wallet_rows, 1):
        asset = r[2].split(" / ")[0]
        uuid = r[1]
        address = r[3]
        balance = r[4]
        explorer = _explorer_url(asset, address)
        address_html = _html_link(address, explorer) if address else "<em>Not stored</em>"
        key_values = private_keys_by_uuid.get(uuid, [])
        if key_values:
            keys_html = "<br>".join(
                f"<strong>{html.escape(scope.split(' / ')[-1])}:</strong> "
                f"<code style=\"white-space:normal;overflow-wrap:anywhere;\">{html.escape(str(value))}</code>"
                for scope, value in key_values
            )
        else:
            keys_html = "<em>Not recovered</em>"
        wallet_table_rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td>{html.escape(r[0])}</td>"
            f"<td><strong>{html.escape(asset)}</strong></td>"
            f"<td><code>{html.escape(uuid)}</code></td>"
            f"<td style=\"overflow-wrap:anywhere;\">{address_html}</td>"
            f"<td>{html.escape(str(balance))}</td>"
            f"<td style=\"overflow-wrap:anywhere;\">{keys_html}</td>"
            "</tr>"
        )

    if not wallet_table_rows:
        wallet_table_rows.append('<tr><td colspan="7">No wallet records were recovered.</td></tr>')

    source_items = "".join(f"<li><code>{html.escape(x)}</code></li>" for x in source_names[:12])
    if len(source_names) > 12:
        source_items += f"<li>+{len(source_names) - 12} additional file(s)</li>"

    non_zero_txt = "No non-zero visible balance found."
    if non_zero_wallets:
        nz = []
        for r in non_zero_wallets:
            asset = r[2].split(" / ")[0]
            nz.append(f"{html.escape(asset)} / {html.escape(r[1])}: <strong>{html.escape(str(r[4]))}</strong>")
        non_zero_txt = "; ".join(nz)

    validation_by_name = {}
    for validation_row in mnemonic_validation_rows:
        validation_by_name.setdefault(validation_row[1], validation_row)

    mnemonic_cards = []
    seen_mnemonics = set()
    for mnemonic_row in mnemonic_rows:
        mnemonic_value = mnemonic_row[3]
        if mnemonic_value in seen_mnemonics:
            continue
        seen_mnemonics.add(mnemonic_value)
        validation_row = validation_by_name.get(mnemonic_row[1])
        status = validation_row[3] if validation_row else "Not validated"
        validation_notes = validation_row[5] if validation_row else ""
        valid = status.startswith("Valid BIP-39")
        badge_color = "#146c43" if valid else "#b02a37"
        mnemonic_cards.append(
            '<div style="border:1px solid #d0d0d0;border-radius:6px;padding:10px;margin:8px 0;background:#ffffff;">'
            f'<p><strong>Mnemonic:</strong> <code style="white-space:normal;overflow-wrap:anywhere;">{html.escape(str(mnemonic_value))}</code></p>'
            f'<p><strong>Validation:</strong> <span style="color:{badge_color};font-weight:bold;">{html.escape(status)}</span></p>'
            f'<p><small>{html.escape(validation_notes)}</small></p>'
            '</div>'
        )
    if not mnemonic_cards:
        mnemonic_cards.append('<p><em>No mnemonic was recovered from the decrypted JSON.</em></p>')

    unique_private_values = {r[3] for r in private_key_rows if r[3]}
    unique_master_values = {r[3] for r in master_key_rows if r[3]}

    scan_status_items = "".join(
        f"<li><code>{html.escape(str(row[3]))}</code> — {html.escape(str(row[6]))}</li>"
        for row in scan_summary_rows
    )
    if not scan_status_items:
        scan_status_items = "<li>No RKStorage scan summary was produced.</li>"

    parser_alert = ""
    if parse_error_rows:
        parser_alert = (
            '<div style="border:2px solid #b02a37;border-radius:6px;padding:10px;margin:12px 0;background:#fff3f3;">'
            '<strong>RKStorage parse error:</strong> '
            + "<br>".join(html.escape(str(row[3])) for row in parse_error_rows)
            + '</div>'
        )
    elif backup_not_found_rows:
        parser_alert = (
            '<div style="border:2px solid #cc8500;border-radius:6px;padding:10px;margin:12px 0;background:#fff8e6;">'
            '<strong>RKStorage was opened, but no Guarda backup object was recognized.</strong> '
            'See the RKStorage Diagnostic rows in the detailed table for the detected tables, columns and record counts.'
            '</div>'
        )

    return f"""
<div style="border:1px solid #cccccc; border-radius:8px; padding:14px; margin:12px 0 18px 0; background:#f8f9fa;">
  <h3 style="margin-top:0;">Application Forensic Summary</h3>
  <p><strong>Analyzed application:</strong> Guarda Crypto Wallet / Crypto Multiwallet</p>
  <p><strong>Android package:</strong> <code>{APP_PACKAGE}</code></p>
  <p><strong>Primary artifact:</strong> <code>databases/RKStorage</code> — React Native AsyncStorage containing persisted wallet state.</p>
  <p><strong>Number of top-level wallets:</strong> {len(wallet_rows)}</p>
  <p><strong>Unique public addresses:</strong> {len(unique_addresses)}</p>
  <p><strong>Tokens/SubWallets:</strong> {len(token_rows)} | <strong>Token contracts:</strong> {len(contract_rows)}</p>
  <p><strong>Non-zero visible balances:</strong> {len(non_zero_wallets)} — {non_zero_txt}</p>
  <p><strong>Recovered evidence:</strong> unique mnemonics={len(seen_mnemonics)}; private-key values={len(unique_private_values)}; internal masterPassword values={len(unique_master_values)}.</p>

  <h4>RKStorage parser status</h4>
  <ul>{scan_status_items}</ul>
  {parser_alert}

  <h4>Recovered mnemonic and BIP-39 validation</h4>
  {''.join(mnemonic_cards)}

  <h4>Wallets recovered from the decrypted JSON</h4>
  <div style="overflow-x:auto;">
    <table class="table table-striped table-bordered table-sm">
      <thead><tr><th>#</th><th>Type</th><th>Asset</th><th>UUID / Identifier</th><th>Public Address</th><th>Balance</th><th>Private Key(s)</th></tr></thead>
      <tbody>{''.join(wallet_table_rows)}</tbody>
    </table>
  </div>

  <h4>Relevant files analyzed</h4>
  <ul>
    {source_items or '<li>No relevant file was processed.</li>'}
  </ul>

  <div style="border:2px solid #b02a37; border-radius:6px; padding:10px; margin:12px 0; background:#fff3f3;">
    <strong>Warning:</strong> the mnemonic and private keys displayed above may permit control of the recovered wallet. Protect this report as confidential evidence.
  </div>

  <p><strong>Backup:</strong> {'identified and parsed' if backup_rows else 'not identified'}.</p>
  <p><strong>Backup decryption:</strong> {'successful in memory for ' + str(len(decryption_successes)) + ' source(s)' if decryption_successes else 'not completed (internal masterPassword unavailable or decryption failed)'}.</p>
  <p><strong>Detailed table:</strong> contains the mnemonic validation result, wallet identifiers, addresses, balances, private keys, backup metadata and decryption provenance.</p>
  <p><strong>Cleanup/deduplication:</strong> {skipped_duplicates} duplicate file(s) ignored; cache, Firebase/Google, Crashlytics, and journal artifacts are removed whenever possible.</p>
</div>
"""


def _write_guarda_html_report(report_folder, detailed_rows, source_path, top_html):
    artifact_name = __artifacts_v2__["crypto_multiwallet_guarda"]["name"]
    description = __artifacts_v2__["crypto_multiwallet_guarda"]["description"]
    if ArtifactHtmlReport is None:
        return
    report = ArtifactHtmlReport(artifact_name)
    report.start_artifact_report(report_folder, artifact_name, description)
    report.add_script()
    report.write_raw_html(top_html)
    data_headers = ("Artifact Type", "Name / UUID", "Asset / Scope", "Address or Value", "Balance", "Notes", "Source File")
    report.write_artifact_data_table(data_headers, detailed_rows, source_path)
    report.end_artifact_report()


def crypto_multiwallet_guarda(files_found, report_folder, seeker, wrap_text):
    rows = []
    processed_sources = []
    seen_file_sha = {}
    skipped_duplicates = 0
    files_found = list(files_found)
    master_password_candidates = _collect_master_password_candidates(files_found)

    for file_found in files_found:
        path = str(file_found)
        if not os.path.isfile(path):
            continue
        if _should_skip_file(path):
            continue
        try:
            sha = _sha256_file(path)
        except Exception:
            sha = ""
        if sha and sha in seen_file_sha:
            skipped_duplicates += 1
            continue
        if sha:
            seen_file_sha[sha] = path
        parsed = _parse_file(path, master_password_candidates)
        if parsed:
            processed_sources.append(path)
            rows.extend(parsed)

    if skipped_duplicates:
        rows.append(_row("Deduplication", "duplicate files skipped", "", skipped_duplicates, "", "Files with identical SHA-256 were ignored", ""))

    # Deduplicate rows by semantic value, not by source, so repeated token addresses do not flood reports.
    detailed_rows = []
    seen = set()
    for row in rows:
        kind, name, asset, value, balance, notes, source = row
        if kind in {
            "Wallet Account", "Token/SubWallet", "Token Contract", "Address Candidate", "Balance",
            "Wallet Identifier", "Private Key", "Mnemonic", "Mnemonic Validation",
            "Wallet Summary", "Internal Decryption Key", "Encrypted Backup",
        }:
            key = (kind, name, asset, value, balance, notes)
        else:
            key = row
        if key in seen:
            continue
        seen.add(key)
        detailed_rows.append(row)

    data_headers = ("Artifact Type", "Name / UUID", "Asset / Scope", "Address or Value", "Balance", "Notes", "Source File")
    source_path = "\n".join(processed_sources)

    if detailed_rows:
        logfunc(f"Found {len(detailed_rows):,} records for Crypto Multiwallet Guarda Wallet")
        top_html = _build_guarda_top_html(detailed_rows, processed_sources, skipped_duplicates)
        _write_guarda_html_report(report_folder, detailed_rows, source_path, top_html)
        tsv(report_folder, data_headers, detailed_rows, "Crypto Multiwallet Guarda Wallet")
    else:
        logfunc("No data found for Crypto Multiwallet Guarda Wallet")

    return data_headers, detailed_rows, source_path



def _collect_files_from_path(input_path):
    input_path = pathlib.Path(input_path)
    if input_path.is_file():
        return [str(input_path)]

    patterns = [
        "**/com.crypto.multiwallet/databases/RKStorage",
        "**/guarda_*rkstorage.json",
        "**/RKStorage*.json",
        "**/com.crypto.multiwallet/files/*/backup*.txt",
        "**/com.crypto.multiwallet/files/mmkv/mmkv.default",
        "**/com.crypto.multiwallet/files/mmkv/mmkv.default.crc",
        "**/com.crypto.multiwallet/shared_prefs/com.crypto.multiwallet_preferences.xml",
        "**/com.crypto.multiwallet/shared_prefs/react-native-device-info.xml",
        "**/com.crypto.multiwallet/shared_prefs/WebViewChromiumPrefs.xml",
        "**/com.crypto.multiwallet/app_webview/Default/Cookies",
        "**/com.crypto.multiwallet/app_webview/Default/Local Storage/leveldb/000*.log",
    ]
    files = []
    for pattern in patterns:
        files.extend(str(p) for p in input_path.glob(pattern) if p.is_file())

    if input_path.name == APP_PACKAGE:
        direct_patterns = [
            "databases/RKStorage", "guarda_*rkstorage.json", "RKStorage*.json", "files/*/backup*.txt", "files/mmkv/mmkv.default", "files/mmkv/mmkv.default.crc",
            "shared_prefs/com.crypto.multiwallet_preferences.xml", "shared_prefs/react-native-device-info.xml", "shared_prefs/WebViewChromiumPrefs.xml",
            "app_webview/Default/Cookies", "app_webview/Default/Local Storage/leveldb/000*.log",
        ]
        for pattern in direct_patterns:
            files.extend(str(p) for p in input_path.glob(pattern) if p.is_file())

    return sorted(set(files))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python crypto_multiwallet_guarda.py <extracted_android_folder_or_package_folder> [output.tsv]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_tsv = sys.argv[2] if len(sys.argv) > 2 else "crypto_multiwallet_guarda_report.tsv"

    files = _collect_files_from_path(input_path)
    headers, data, source_path = crypto_multiwallet_guarda(files, ".", None, False)

    with open(output_tsv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)
        writer.writerows(data)

    print(f"Processed candidate files: {len(files)}")
    print(f"Rows written: {len(data)}")
    print(f"Output: {output_tsv}")
