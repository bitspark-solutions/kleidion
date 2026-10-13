// Client-side security health ("Watchtower-lite"), Phase 5 contract Step B.
// Pure functions over ALREADY-DECRYPTED plaintext — the server never sees any
// of this. No crypto imports here by design (scoring is deterministic).

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export interface PasswordScore {
  /** 0 = critical … 4 = excellent. */
  score: 0 | 1 | 2 | 3 | 4;
  reasons: string[];
}

/**
 * A curated list of frequently leaked passwords (top-N style). Lowercase
 * keys; input is lowercased/NFKC-normalized before lookup.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set(
  ("password,123456,12345678,qwerty,abc123,1234567,111111,123456789," +
    "12345,123123,money,phoenix,ninja,password1,dragon,123qwe,654321," +
    "mustang,letmein,1234567890,football,iloveyou,password123,monkey," +
    "shadow,131313,121212,666666,mylove,root,qwer1234,admin, qwerty123," +
    "welcome,login,princess,star,solo,pass,anything,fuckyou,michael," +
    "jennifer,computer,superman,batman,trustno1,tigger,silver,ginger," +
    "internet,samantha,openup,7777777,8750413,mypass,abcdef,abcd1234," +
    "1q2w3e4r,1qaz2wsx,qazwsx,soccer,hockey,killer,buster,sorcerer," +
    "harley,cheese,pepper,ginger,jester,dan123,summer,ashley,nicole," +
    "jessica,austin,daniel,chelsea,zxcvbnm,zaq12wsx,jordan23,passw0rd," +
    "p@ssw0rd,pa55word,hello,master,admin123,letmein123,changeme," +
    "default,guest,starwars,darthmaul,corvette,access,flower,sunny," +
    "samsung,gateway,peanut,mickey,winx,1212,0000,000000,123321," +
    "696969,888888,7654321,159753,123654,987654321,poohbear,brian," +
    "victoria,george,snickers,charlie,robert,matthew,anthony,william," +
    "thomas,cooper,dexter,blood,bandit,browny,braves,dallas,boston," +
    "lovers,allah,marlboro,miller,jackson,apple,newton,meow,vanessa," +
    "picard,ladies,cookie,chester,joshua,michael1,12qwaszx,madison," +
    "diamond,biteme,steven,london,secret,mike,nancy,marcus,blazer," +
    "panties,ferrari,knight,hardcore,malcolm,cool,buddy,dolphins," +
    "bond007,white,rainbow,precious,bob,bobby,apache,banana,chevy," +
    "spirit,tennis,hunter2,yahoo,winston,crystal,golfer,shannon," +
    "murphy,randy,thunder,casino,taylor,boomer,wolf,soldiers,point," +
    "mother,50cent,7,alex,4,abgrtyu,action,albert,alexander,brandi," +
    "aaron,amber,angela,anthony1,asdfgh,beach,beatles,blabla,blank," +
    "charlie1,chris,chelsea1,cinder,computer1,corona,cumming,cyber," +
    "denise,doctor,donald,domino,electra,einstein,element,eric,expert," +
    "fender,felix,flintstones,flex,forest,franklin,freaky,free,freedom," +
    "gandalf,garfield,gene,genesis,genius,gilles,graham,grant,great," +
    "hannah,health,helpme,horizon,indian,indiana,insane,ironman,jason," +
    "jasper,jazz,jasper,jerry,jessica1,jimmy,johnny,jordan,joseph,justin," +
    "kevin,klapaucius,laptop,latex,laurel,leather,letitbe,liquid,lisa," +
    "loulou,lucky,maggie,manual,mazda,mercury,merlin,michael2,michelle," +
    "windows,miller1,minnie,miracle,molly,monica,morgan,ncc1701,newlife," +
    "newport,nicholas,nicole1,nirvana,number1,oliver,outlaw,packers,pakistan," +
    "patrick,penguin,pentium,people,pete,philip,piano,pizza,platinum,pokemon," +
    "portugal,preggo,privat,prodigy,psycho,pumpkin,purple,queen,querty,quincy," +
    "racing,rammstein,ranger,rapunzel,rebecca,red,redwing,regexp,retard,rene," +
    "renee,roll,romeo,rommel,ronald,roses,sailor,salmon,sammy,sandra,scooby," +
    "scorpio,scott,scruffy,seinfeld,sex,shaddy,sharon,shaved,shit,shocker," +
    "showtime,skeater,skippy,smask,smile,snatch,snoopy,snoopy1,solar,solid," +
    "somebody,sonny,spanky,sparky,speedy,spencer,sphere,spring,sqdw,ss,star," +
    "start,sting,stalker,sterling,stone,stefan,stephanie,steel,stonecol," +
    "stupid,success,suckit,sunrise,super,danny,sylvia,synapse,system,tamara," +
    "tara,tarheel,teddy,temp,testing,the,theo,therock,thick,tiffany,tito," +
    "tomcat,toronto,trend,trooper,truck,tt,tuesday,turkey,twinkie,tyler," +
    "uber,uccello,ucla,ultra,unreal,unlock,upsman,uranus,usmc,utah,vdub," +
    "vengeance,victor,video,viking,viper,vipergts,vice,vicious,vikki,village," +
    "vince,virgin,voodoo,voyager,vulcan,wade,walley,walter,wanker,warren," +
    "warrior,water,wayne,weasel,webmaster,wendy,werner,wesley,whale,whatever," +
    "wheeling,whiskey,wildcat,will,wilson,winnie,winter,wizard,yamaha,yankee," +
    "yellow,young,zachary,zombie,correcthorsebatterystaple,horsebattery," +
    "passwort,contrasena,kotik,qwertyuiop,asdfghjkl,zxcvbnm1,147258,2580," +
    "qwe123,qweasd,asd123,zaq1,1q2q3q,55555,5555,4444,3333,2222,111,000," +
    "123456a,abcdefg,abcdef123,qazxsw,112233,12344321,987456321,159357," +
    "741852963,741000,741100,1002101012,abcabc,ababab,aaaaaa,aaabbb")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
);

const ALPHABET_SEQ = "abcdefghijklmnopqrstuvwxyz";
const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
const DIGIT_SEQ = "0123456789";

function codePoints(s: string): string[] {
  return Array.from(s);
}

/** True when `s` contains a run of >= `n` consecutive alphabet/digit/keyboard chars (forward or reversed). */
function hasSequence(s: string, n = 4): boolean {
  const low = s.toLowerCase();
  const alphabet = ALPHABET_SEQ + ALPHABET_SEQ;
  const digits = DIGIT_SEQ + DIGIT_SEQ;
  const haystacks = [
    alphabet,
    [...alphabet].reverse().join(""),
    digits,
    [...digits].reverse().join(""),
    ...KEYBOARD_ROWS,
    ...KEYBOARD_ROWS.map((r) => [...r].reverse().join("")),
  ];
  for (const hay of haystacks) {
    for (let i = 0; i + n <= hay.length; i++) {
      if (low.includes(hay.slice(i, i + n))) return true;
    }
  }
  return false;
}

/** True when any character repeats 3+ times consecutively (aaa, 111, ...). */
function hasRepeat(s: string): boolean {
  let run = 1;
  const chars = codePoints(s);
  for (let i = 1; i < chars.length; i++) {
    run = chars[i] === chars[i - 1] ? run + 1 : 1;
    if (run >= 3) return true;
  }
  return false;
}

/**
 * Heuristic 0–4 score for a plaintext password (zxcvbn-lite): common-password
 * blocklist, length bands, character-class variety, sequences and repeats.
 * `entropyBits` (from @kleidion/crypto pool math) only raises the floor for
 * long generated passwords — it can never rescue a blocklisted one.
 */
export function scorePassword(
  pw: string,
  opts: { entropyBits?: number } = {},
): PasswordScore {
  const reasons: string[] = [];
  if (!pw) return { score: 0, reasons: ["No password set"] };

  const norm = pw.normalize("NFKC").toLowerCase();
  if (COMMON_PASSWORDS.has(norm)) {
    return { score: 0, reasons: ["This is a well-known leaked password"] };
  }

  const len = codePoints(pw).length;
  const classes =
    (/[a-z]/.test(pw) ? 1 : 0) +
    (/[A-Z]/.test(pw) ? 1 : 0) +
    (/[0-9]/.test(pw) ? 1 : 0) +
    (/[^a-zA-Z0-9]/.test(pw) ? 1 : 0);

  let score: 0 | 1 | 2 | 3 | 4 = 0;
  if (len >= 8) score = 1;
  if (len >= 12 && classes >= 2) score = 2;
  if (len >= 16 && classes >= 3) score = 3;
  if (len >= 20 && classes >= 4) score = 4;

  // Generated-password floor: high pool entropy with no structural weakness.
  if ((opts.entropyBits ?? 0) >= 60 && score < 3 && !hasSequence(pw) && !hasRepeat(pw)) {
    score = 3;
  }

  // Structural penalties (caps, applied after the floor).
  if (len < 8) {
    score = Math.min(score, 0) as 0;
    reasons.push("Shorter than 8 characters");
  }
  if (classes <= 1 && len < 16) {
    score = Math.min(score, 1) as 0 | 1;
    reasons.push("Uses only one character type");
  }
  if (hasSequence(pw)) {
    score = Math.min(score, 1) as 0 | 1;
    reasons.push("Contains a common sequence (abc, 123, qwerty…)");
  }
  if (hasRepeat(pw)) {
    score = Math.min(score, 1) as 0 | 1;
    reasons.push("Contains repeated characters");
  }
  if (score <= 1) reasons.push("Consider regenerating this password");

  return { score, reasons };
}

// ---------------------------------------------------------------------------
// Reuse detection
// ---------------------------------------------------------------------------

export interface ReusableLogin {
  id: string;
  password: string;
}

/**
 * Group logins by their exact plaintext password. Only passwords shared by
 * 2+ logins are returned. Empty passwords are ignored. Comparison is on the
 * decrypted values — NEVER on searchHmac (keyed per vault; wrong tool).
 */
export function findReuse<T extends ReusableLogin>(
  logins: T[],
): Map<string, T[]> {
  const byPassword = new Map<string, T[]>();
  for (const l of logins) {
    if (!l.password) continue;
    const arr = byPassword.get(l.password);
    if (arr) arr.push(l);
    else byPassword.set(l.password, [l]);
  }
  for (const [pw, arr] of byPassword) {
    if (arr.length < 2) byPassword.delete(pw);
  }
  return byPassword;
}

// ---------------------------------------------------------------------------
// Age
// ---------------------------------------------------------------------------

/** True when an item hasn't been updated in `days` (default 180). */
export function isOld(updatedAtIso: string, days = 180, now: number = Date.now()): boolean {
  const t = Date.parse(updatedAtIso);
  if (Number.isNaN(t)) return false;
  return now - t > days * 24 * 60 * 60 * 1000;
}
