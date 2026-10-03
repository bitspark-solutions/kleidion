// Password + passphrase generation (master plan §5: `generatePassword(recipe)` /
// `generatePassphrase`). Pure client-side; every random draw comes from the
// libsodium CSPRNG — Math.random is NEVER used anywhere in this module.
//
// Unbiased selection: we draw via sodium's `randombytes_uniform(upper)`, which
// implements REJECTION SAMPLING internally (it discards draws >= the largest
// multiple of `upper` below 2^32), so there is no modulo bias. Documented here
// per the API contract.

import { ready } from "./sodium";

// --- Character classes -------------------------------------------------------

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
 * Characters removed when `excludeAmbiguous` is set: visually confusable
 * glyphs (I/l/1, O/0, |, `, ', "). Exactly these 9 — kept minimal so every
 * class still has members after filtering.
 */
const AMBIGUOUS = "Il1O0|`'\"";

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;
export const DEFAULT_PASSWORD_LENGTH = 20;

export interface PasswordRecipe {
  /** Target length; clamped to 8..128 (default 20 when missing/invalid). */
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  /** Drop visually confusable characters (I, l, 1, O, 0, |, `, ', "). */
  excludeAmbiguous: boolean;
  /** Extra characters to strip from every class (e.g. shell metacharacters). */
  exclude?: string;
}

export interface PassphraseRecipe {
  /** Number of words; default 6, clamped to 1..32. */
  words: number;
  /** Separator between words; default "-". */
  separator: string;
  /** Uppercase the first letter of each word. */
  capitalize: boolean;
  /** Append a random 0-9999 token (4 digits, zero-padded) after a separator. */
  includeNumber: boolean;
}

// --- Wordlist ----------------------------------------------------------------
//
// WORDLIST_SIZE = 1024 words (10 bits/word). Source: first 1024 unique
// lowercase alpha words (4-8 chars) of the Google 10k English list
// (first20hours/google-10000-english, "no-swears" variant) — used as an
// EFF-large-style stand-in because eff.org was unreachable at authoring time.
// Embedded verbatim; no network access, no extra dependencies.

const WORDLIST_CSV =
  "that,this,with,from,your,have,more,will,home,about,page,search,free,other,time,they,site,what,"
+ "which,their,news,there,only,when,contact,here,business,also,help,view,online,first,been,would,"
+ "were,services,some,these,click,like,service,than,find,price,date,back,people,list,name,just,"
+ "over,state,year,into,email,health,world,next,used,work,last,most,products,music,data,make,them,"
+ "should,product,system,post,city,policy,number,such,please,support,message,after,best,software,"
+ "then,good,video,well,where,info,rights,public,books,high,school,through,each,links,review,years,"
+ "order,very,privacy,book,items,company,read,group,need,many,user,said,does,under,general,"
+ "research,january,mail,full,reviews,program,life,know,games,days,part,could,great,united,hotel,"
+ "real,item,center,ebay,must,store,travel,comments,made,report,member,details,line,terms,before,"
+ "hotels,send,right,type,because,local,those,using,results,office,national,design,take,posted,"
+ "internet,address,within,states,area,want,phone,shipping,reserved,subject,between,forum,family,"
+ "long,based,code,show,even,black,check,special,prices,website,index,being,women,much,sign,file,"
+ "link,open,today,south,case,project,same,pages,version,section,found,sports,house,related,"
+ "security,both,county,american,photo,game,members,power,while,care,network,down,computer,systems,"
+ "three,total,place,download,without,access,think,north,current,posts,media,control,water,history,"
+ "pictures,size,personal,since,guide,shop,board,location,change,white,text,small,rating,rate,"
+ "children,during,return,students,shopping,account,times,sites,level,digital,profile,previous,"
+ "form,events,love,john,main,call,hours,image,title,another,shall,property,class,still,money,"
+ "quality,every,listing,content,country,private,little,visit,save,tools,reply,customer,december,"
+ "compare,movies,include,college,value,article,york,card,jobs,provide,food,source,author,press,"
+ "learn,sale,around,print,course,canada,process,teen,room,stock,training,credit,point,join,"
+ "science,advanced,west,sales,look,english,left,team,estate,select,windows,photos,thread,week,"
+ "category,note,live,large,gallery,table,register,however,june,october,november,market,library,"
+ "really,action,start,series,model,features,industry,plan,human,provided,required,second,cost,"
+ "movie,forums,march,better,july,yahoo,going,medical,test,friend,come,server,study,cart,staff,"
+ "articles,feedback,again,play,looking,issues,april,never,users,complete,street,topic,comment,"
+ "things,working,against,standard,person,below,mobile,less,blog,party,payment,login,student,"
+ "programs,offers,legal,above,recent,park,stores,side,problem,give,memory,social,august,quote,"
+ "language,story,sell,options,rates,create,body,young,america,field,east,paper,single,club,"
+ "example,girls,password,latest,road,gift,question,changes,night,hard,texas,four,poker,status,"
+ "browse,issue,range,building,seller,court,february,always,result,audio,light,write,offer,blue,"
+ "groups,easy,given,files,event,release,analysis,request,china,making,picture,needs,possible,"
+ "might,month,major,star,areas,future,space,hand,cards,problems,london,meeting,become,interest,"
+ "child,keep,enter,share,similar,garden,schools,million,added,listed,baby,learning,energy,"
+ "delivery,popular,term,film,stories,journal,reports,welcome,central,images,notice,original,head,"
+ "radio,until,cell,color,self,council,away,includes,track,archive,once,others,format,least,"
+ "society,months,safety,friends,sure,trade,edition,cars,messages,tell,further,updated,able,having,"
+ "provides,david,already,green,studies,close,common,drive,specific,several,gold,living,called,"
+ "short,arts,display,limited,powered,means,director,daily,beach,past,natural,whether,five,upon,"
+ "period,planning,database,says,official,weather,land,average,done,window,france,region,island,"
+ "record,direct,records,district,calendar,costs,style,front,update,parts,ever,early,miles,sound,"
+ "resource,present,either,document,word,works,material,bill,written,talk,federal,hosting,rules,"
+ "final,adult,tickets,thing,centre,cheap,kids,finance,true,minutes,else,mark,third,rock,gifts,"
+ "europe,reading,topics,tips,plus,auto,cover,usually,edit,together,videos,percent,fast,function,"
+ "fact,unit,getting,global,tech,meet,economic,player,projects,lyrics,often,submit,germany,amount,"
+ "watch,included,feel,though,bank,risk,thanks,deals,various,words,linux,james,weight,town,heart,"
+ "received,choose,archives,points,magazine,error,camera,girl,toys,clear,golf,receive,domain,"
+ "methods,chapter,makes,policies,loan,wide,beauty,manager,india,position,taken,sort,listings,"
+ "models,michael,known,half,cases,step,florida,simple,quick,none,wireless,license,paul,friday,"
+ "lake,whole,annual,later,basic,sony,shows,google,church,method,purchase,active,response,practice,"
+ "hardware,figure,fire,holiday,chat,enough,designed,along,among,death,writing,speed,html,loss,"
+ "face,brand,discount,higher,effects,created,remember,yellow,increase,kingdom,base,near,thought,"
+ "stuff,french,storage,japan,doing,loans,shoes,entry,stay,nature,orders,africa,summary,turn,mean,"
+ "growth,notes,agency,king,monday,european,activity,copy,although,drug,pics,western,income,force,"
+ "cash,overall,river,package,contents,seen,players,engine,port,album,regional,stop,supplies,"
+ "started,views,plans,double,build,screen,exchange,types,soon,lines,continue,across,benefits,"
+ "needed,season,apply,someone,held,anything,printer,believe,effect,asked,mind,sunday,casino,lost,"
+ "tour,menu,volume,cross,anyone,mortgage,hope,silver,wish,inside,solution,mature,role,rather,"
+ "weeks,addition,came,supply,nothing,certain,running,lower,union,jewelry,clothing,fine,names,"
+ "robert,homepage,hour,skills,bush,islands,advice,career,military,rental,decision,leave,british,"
+ "teens,huge,woman,kind,sellers,middle,move,cable,taking,values,division,coming,tuesday,object,"
+ "lesbian,machine,logo,length,actually,nice,score,client,returns,capital,follow,sample,sent,shown,"
+ "saturday,england,culture,band,flash,lead,george,choice,went,starting,thursday,courses,consumer,"
+ "airport,foreign,artist,outside,levels,channel,letter,mode,phones,ideas,fund,summer,allow,degree,"
+ "contract,button,releases,homes,super,male,matter,custom,virginia,almost,took,located,multiple,"
+ "asian,editor,cause,song,cnet,focus,late,fall,featured,idea,rooms,female,thomas,primary,cancer,"
+ "numbers,reason,tool,browser,spring,answer,voice,friendly,schedule,purpose,feature,comes,police,"
+ "everyone,approach,cameras,brown,physical,hill,maps,medicine,deal,hold,ratings,chicago,forms,"
+ "glass,happy,smith,wanted,thank,safe,unique,survey,prior,sport,ready,feed,animal,sources,mexico,"
+ "regular,secure,simply,evidence,station,round,paypal,favorite,option,master,valley,recently,"
+ "probably,rentals,built,blood,improve,hall,larger,anti,networks,earth,parents,nokia,impact,"
+ "transfer,kitchen,strong,carolina,wedding,hospital,ground,overview,ship,owners,disease,paid,"
+ "italy,perfect,hair,classic,basis,command,cities,william,express,award,distance,tree,peter,"
+ "ensure,thus,wall,involved,extra,partners,budget,rated";

/** The embedded passphrase wordlist (see source comment above). */
export const WORDLIST: readonly string[] = WORDLIST_CSV.split(",");

/** Number of words in the embedded wordlist (1024 → 10 bits per word). */
export const WORDLIST_SIZE = WORDLIST.length;

// --- Internals ----------------------------------------------------------------

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function filterClass(set: string, excludeAmbiguous: boolean, exclude: string): string {
  let out = set;
  if (excludeAmbiguous) out = out.replace(/[Il1O0|`'"]/g, "");
  if (exclude) {
    for (const ch of new Set(exclude)) out = out.split(ch).join("");
  }
  return out;
}

function buildClasses(recipe: PasswordRecipe): string[] {
  const excl = recipe.exclude ?? "";
  const classes: string[] = [];
  if (recipe.upper) classes.push(filterClass(UPPER, recipe.excludeAmbiguous, excl));
  if (recipe.lower) classes.push(filterClass(LOWER, recipe.excludeAmbiguous, excl));
  if (recipe.digits) classes.push(filterClass(DIGITS, recipe.excludeAmbiguous, excl));
  if (recipe.symbols) classes.push(filterClass(SYMBOLS, recipe.excludeAmbiguous, excl));
  if (classes.length === 0) {
    throw new Error("generatePassword: at least one character class must be enabled");
  }
  for (const c of classes) {
    if (c.length === 0) {
      throw new Error("generatePassword: exclusions emptied an enabled character class");
    }
  }
  return classes;
}

function normalizeLength(recipe: PasswordRecipe): number {
  const raw = Number.isFinite(recipe.length) ? recipe.length : DEFAULT_PASSWORD_LENGTH;
  return clamp(Math.floor(raw), MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
}

/** Unbiased integer in [0, n) via libsodium rejection sampling. */
async function randomInt(n: number): Promise<number> {
  const s = await ready();
  return s.randombytes_uniform(n);
}

// --- Password ------------------------------------------------------------------

/**
 * Generate a random password from a CSPRNG (libsodium). Guarantees at least
 * one character from EVERY enabled class, then Fisher-Yates shuffles so the
 * guaranteed characters are not positionally identifiable. Length is clamped
 * to 8..128 (default 20).
 */
export async function generatePassword(recipe: PasswordRecipe): Promise<string> {
  const classes = buildClasses(recipe);
  const length = normalizeLength(recipe);
  if (length < classes.length) {
    throw new Error("generatePassword: length too short for the enabled classes");
  }
  const pool = classes.join("");

  const chars: string[] = [];
  // One guaranteed character per enabled class.
  for (const c of classes) chars.push(c[await randomInt(c.length)]);
  // Fill the remainder from the combined pool.
  while (chars.length < length) chars.push(pool[await randomInt(pool.length)]);

  // Fisher-Yates shuffle (unbiased draws).
  for (let i = chars.length - 1; i > 0; i--) {
    const j = await randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

// --- Passphrase ----------------------------------------------------------------

/**
 * Generate a diceware-style passphrase: `words` words drawn CSPRNG-unbiasedly
 * from the embedded wordlist, joined by `separator` (default "-"). With
 * `includeNumber`, a random 0-9999 token zero-padded to 4 digits is appended
 * after another separator. Defaults: 6 words.
 */
export async function generatePassphrase(recipe: PassphraseRecipe): Promise<string> {
  const words = clamp(
    Number.isFinite(recipe.words) ? Math.floor(recipe.words) : 6,
    1,
    32,
  );
  const sep = recipe.separator ?? "-";

  const parts: string[] = [];
  for (let i = 0; i < words; i++) {
    let w = WORDLIST[await randomInt(WORDLIST_SIZE)];
    if (recipe.capitalize) w = w[0].toUpperCase() + w.slice(1);
    parts.push(w);
  }
  if (recipe.includeNumber) {
    const n = await randomInt(10000);
    parts.push(String(n).padStart(4, "0"));
  }
  return parts.join(sep);
}

// --- Entropy + strength ----------------------------------------------------------

/**
 * Theoretical entropy of a password recipe: log2(charset^length) =
 * length * log2(charsetSize), using the SAME charset filtering (classes,
 * excludeAmbiguous, exclude) and length clamping as generatePassword.
 */
export function passwordEntropyBits(recipe: PasswordRecipe): number {
  let charset = 0;
  try {
    charset = buildClasses(recipe).join("").length;
  } catch {
    return 0; // no enabled class → no entropy
  }
  // Pool may contain no duplicates (classes are disjoint), so size = sum.
  return normalizeLength(recipe) * Math.log2(charset);
}

/**
 * Theoretical entropy of a passphrase recipe: log2(wordlistSize^words) =
 * words * log2(WORDLIST_SIZE). Per the API contract the optional number token
 * is not counted here.
 */
export function passphraseEntropyBits(recipe: PassphraseRecipe): number {
  const words = clamp(
    Number.isFinite(recipe.words) ? Math.floor(recipe.words) : 6,
    1,
    32,
  );
  return words * Math.log2(WORDLIST_SIZE);
}

/**
 * Human-readable strength label. Thresholds (bits):
 *   < 28        → "very weak"
 *   28 .. <36   → "weak"
 *   36 .. <60   → "fair"
 *   60 .. <128  → "strong"
 *   >= 128      → "very strong"
 */
export function strengthLabel(bits: number): "very weak" | "weak" | "fair" | "strong" | "very strong" {
  if (bits < 28) return "very weak";
  if (bits < 36) return "weak";
  if (bits < 60) return "fair";
  if (bits < 128) return "strong";
  return "very strong";
}
