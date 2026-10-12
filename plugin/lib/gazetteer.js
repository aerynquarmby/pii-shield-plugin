/**
 * First-name gazetteer + honorifics + stopwords, used to anchor heuristic PERSON
 * detection so free-text names get caught WITHOUT flagging every Title-Case phrase
 * (headings, product names, glossary terms) — zero-dep, no ML.
 * Global + African-market-aware. Not exhaustive — clients extend with custom terms,
 * and labelled names ("Name: …", "signed by …") are caught separately.
 */

export const FIRST_NAMES = new Set(
  [
  // ---- Regional expansion ------------------------------------------------------------------
  // Curated by region, NOT scraped. The public corpora were measured first: 22,270 names across
  // two permissively licensed datasets, and zero of the African given names this list was
  // missing. Those datasets ship all/us/es files and are Western by construction, so a bigger
  // generic list buys recall we already had and nothing where the gap actually is.
  //
  // Given names that are also ordinary English words are deliberately EXCLUDED: Grace, Hope,
  // Faith, Precious, Blessing, Gift, Comfort, Patience, Justice, Innocent, Lucky, Given, Talent.
  // They are real and common, particularly in West and Southern Africa, but a gazetteer hit is
  // what licenses masking a Title-Case run in free prose, so including them would mask
  // "Grace Period" and "Hope Street". They are still caught wherever a field or a label declares
  // them, which is the path an ATS record actually travels.
  //
  // Names under four letters are held back for the same reason.
  "abdirahman", "abeba", "abubakar", "adaobi", "adebayo", "adedayo", "adeola", "adesola", "adetokunbo", "adhiambo", "aditi", "adjoa", "aduke", "advait", "afia", "afolabi", "afua", "ahmet", "ajani", "akachi", "akash", "akin", "akinwale", "akinyi", "akira", "akoth", "akua", "akwasi", "alemu", "aliyu", "amaka", "amani", "amarachi", "aminata", "amir", "ampofo", "anayo", "andile", "anika", "ankit", "arash", "arinze", "aryan", "asantewaa", "atieno", "auma", "avni", "awele", "awuor", "axmed", "ayabonga", "aylin", "ayodele", "ayomide", "babajide", "bahar", "bahati", "baraka", "barasa", "baris", "bashir", "bekele", "bhavna", "binta", "boakye", "bohlale", "bolanle", "bongi", "bontle", "bosire", "buhle", "bukola", "burak", "cabdi", "cali", "cheikh", "cheng", "chepkoech", "cheruiyot", "chetan", "chiamaka", "chibueze", "chidera", "chiedozie", "chigozie", "chijioke", "chika", "chikaodili", "chimamanda", "chinelo", "chinwe", "chinyere", "chisom", "chizoba", "chukwudi", "chukwuemeka", "daiki", "damilola", "dariush", "darshan", "deepika", "deniz", "deqa", "desta", "dhruv", "dineo", "divya", "ebele", "ebru", "ebube", "ekene", "emiko", "emre", "eniola", "enitan", "esosa", "esra", "faduma", "farhad", "farzaneh", "fatou", "ferhat", "fhatuwani", "fikile", "fikru", "folasade", "funmilayo", "furaha", "gathoni", "gaurav", "getachew", "githinji", "goitseone", "gokhan", "habiba", "hakan", "hamid", "harsh", "hauwa", "hinata", "hiwot", "hlayiseka", "hlulani", "hodan", "hyun", "idil", "idris", "ifeoma", "ifeyinwa", "ikechukwu", "ilkay", "imani", "ireti", "ishita", "jabari", "jamila", "jatin", "jepkosgei", "jerotich", "jian", "joon", "kaito", "karanja", "kariuki", "kefilwe", "kelechi", "kemal", "kemi", "kemunto", "kerubo", "kgomotso", "khadar", "khadija", "khanyisile", "khaya", "kidist", "kilonzo", "kimani", "kipchoge", "kiplagat", "kiprop", "kipruto", "kiran", "kiyoshi", "koech", "koketso", "krishna", "kunle", "kwadwo", "kwaku", "kwasi", "ladan", "ladi", "lakshmi", "laleh", "langat", "lanre", "lesego", "liang", "liibaan", "ling", "luyanda", "mahesh", "maina", "makokha", "makoto", "mamadou", "manav", "mansa", "maryam", "mbali", "meera", "mehdi", "mekonnen", "menzi", "merve", "mhlengi", "mmapula", "mohit", "moraa", "msizi", "mulalo", "murat", "musyoka", "muthoni", "mutua", "mwikali", "nafisa", "naina", "nandi", "naoki", "nasimiyu", "nasrin", "ndeye", "ndinda", "neema", "nekesa", "nihal", "nikhil", "ning", "nisha", "njeri", "nkechi", "nkiru", "nkosi", "nnamdi", "nolwazi", "nomalanga", "nombuso", "nomfundo", "noriko", "ntandoyenkosi", "nthabiseng", "ntombi", "nuruddin", "nyaboke", "nyakundi", "nyeleti", "nyokabi", "obakeng", "obiageli", "ochieng", "odhiambo", "oghenekaro", "okechukwu", "okoth", "olamide", "olubunmi", "oluchi", "oludare", "olumide", "olusegun", "oluwafemi", "oluwaseun", "oluwatobi", "omid", "omondi", "omphile", "onur", "onyango", "onyeka", "onyinye", "opiyo", "ouma", "ousmane", "owino", "oyinkansola", "ozge", "pallavi", "parisa", "parth", "phumzile", "ping", "pranav", "priyanka", "qiang", "qing", "rajesh", "rakesh", "realeboga", "rehema", "reneilwe", "rethabile", "reza", "risuna", "rivoningo", "rofhiwa", "rohit", "rotich", "roya", "ruchi", "rudzani", "sadiq", "saeed", "sagal", "sagar", "salama", "salma", "sanele", "sang", "satoshi", "sbusiso", "selam", "selim", "serkan", "seung", "seydou", "shan", "shinji", "shirin", "shreya", "sibongile", "siddharth", "sifiso", "simiyu", "simphiwe", "simran", "siphiwe", "sithembiso", "sneha", "sokhna", "sola", "soraya", "subira", "suresh", "swati", "syombua", "takalani", "takumi", "tanui", "tanvi", "tarun", "temitope", "tesfaye", "thabani", "thandeka", "thato", "thembi", "tigist", "tirelo", "titilayo", "tobi", "tolu", "tsakani", "tshiamo", "tshifhiwa", "tsholofelo", "tuba", "tumelo", "uchechi", "uchenna", "ugochukwu", "ulari", "umar", "upendo", "usman", "uzoma", "vaibhav", "varun", "vhutshilo", "vidya", "vikram", "vinay", "vishal", "vuyo", "wairimu", "wambui", "wanjala", "wanjiku", "warsame", "wekesa", "xiang", "xiao", "yang", "yasemin", "yash", "yasmin", "yemi", "yeon", "yohannes", "yong", "young", "yuan", "yuna", "yusuke", "zahra", "zandile", "zawadi", "zerihun", "zeynep", "zhen", "zinhle", "zodwa", "zola", "zubairu",

    // Western / Anglophone — common male
    "james","john","robert","michael","william","david","richard","joseph","thomas","charles",
    "christopher","daniel","matthew","anthony","donald","mark","paul","steven","stephen","andrew",
    "kenneth","joshua","kevin","brian","george","edward","ronald","timothy","jason","jeffrey",
    "ryan","jacob","gary","nicholas","eric","jonathan","stephen","larry","justin","scott",
    "brandon","benjamin","samuel","gregory","alexander","patrick","frank","raymond","jack","dennis",
    "jerry","tyler","aaron","jose","adam","henry","nathan","douglas","peter","zachary",
    "kyle","walter","ethan","jeremy","harold","keith","christian","roger","noah","gerald",
    "carl","terry","sean","austin","arthur","lawrence","jesse","dylan","bryan","joe",
    "jordan","billy","bruce","albert","willie","gabriel","logan","alan","juan","wayne",
    "roy","ralph","randy","eugene","vincent","russell","louis","philip","bobby","johnny",
    "simon","luke","oscar","liam","harry","tom","bob","dave","charlie","max","leo","toby","xavier","ivan","victor","hugo","felix","dominic","marcus","julian","elliot",
    // Western / Anglophone — common female
    "mary","patricia","jennifer","linda","elizabeth","barbara","susan","jessica","sarah","karen",
    "lisa","nancy","betty","margaret","sandra","ashley","kimberly","emily","donna","michelle",
    "carol","amanda","dorothy","melissa","deborah","stephanie","rebecca","sharon","laura","cynthia",
    "kathleen","amy","angela","shirley","anna","brenda","pamela","emma","nicole","helen",
    "samantha","katherine","christine","debra","rachel","carolyn","janet","catherine","maria","heather",
    "diane","olivia","julie","joyce","victoria","kelly","christina","joan","evelyn","judith",
    "megan","andrea","cheryl","hannah","jacqueline","martha","gloria","teresa","ann","sara",
    "madison","frances","kathryn","janice","jean","abigail","alice","julia","judy","sophia",
    "grace","denise","amber","doris","marilyn","danielle","beverly","isabella","theresa","diana",
    "natalie","brittany","charlotte","marie","kayla","alexis","lori","chloe","lucy","ella","kate","nina","jane","zoe","ruby","holly","clara","lily",
    // South / Southern African
    "thabo","sipho","themba","bongani","mandla","lwazi","kagiso","tshepo","katlego","lerato",
    "nomvula","nomsa","thandiwe","zanele","lindiwe","nokuthula","ayanda","sibusiso","bandile","anele",
    "naledi","refilwe","dimpho","boitumelo","palesa","karabo","itumeleng","tebogo","mpho","kabelo",
    "nkosana","vusi","jabu","dumisani","mthunzi","siyabonga","sizwe","thulani","xolani","zweli",
    "nonhlanhla","busisiwe","precious","gugu","hlengiwe","khanyi","lungile","nosipho","phindile","thembeka",
    "johan","pieter","willem","hendrik","francois","gerhard","riaan","marius","stefan","dewald",
    "annelie","marike","chantelle","elmarie","carien","ronel","suraya","tarryn","aneesa","yusra",
    // West / East / North African
    "kwame","kofi","kojo","yaw","kwabena","ama","akosua","adwoa","abena","efua",
    "chidi","chinonso","emeka","obinna","ifeanyi","ngozi","amara","chioma","adaeze","nneka",
    "amina","fatima","aisha","zainab","halima","ibrahim","musa","yusuf","abdul","sekou",
    "kwesi","yaa","nana","femi","tunde","bola","segun","folake","yetunde","chidinma",
    "wanjiru","njoroge","kamau","otieno","achieng","wafula","mwangi","nyambura","kiptoo","chebet",
    // South Asian
    "raj","priya","arjun","anil","sunil","vijay","ravi","amit","rahul","sanjay",
    "deepak","rohan","aditya","ananya","aarav","ishaan","kavya","riya","neha","pooja",
    "aisha","fatima","zara","hassan","bilal","imran","saad","ayesha","mariam","zainab",
    // East Asian
    "wei","li","chen","ming","hui","jing","yan","lei","feng","xin",
    "hiroshi","yuki","haruto","sakura","aiko","kenji","mei","jun","hana","ren",
    "minjun","seoyeon","jiwoo","haeun","jihoon","sena",
    // Hispanic / Lusophone / other European
    "maria","jose","juan","carlos","ana","sofia","lucas","mateo","diego","valentina",
    "miguel","javier","luis","antonio","pedro","manuel","francisco","rafael","gabriela","camila",
    "joao","pedro","tiago","matheus","larissa","beatriz","ivan","dmitri","olga","natasha",
    "hans","greta","lars","freya","anders","ingrid","matteo","giulia","luca","chiara",
  ].map((s) => s.toLowerCase())
);

/** Titles that reliably precede a name ("Mr Smith", "Dr Jane Doe"). */
export const HONORIFICS = new Set(
  ["mr","mrs","ms","miss","mx","dr","prof","professor","sir","madam","dame","rev","reverend","hon","fr","capt","col","sgt","lt","gen"]
);

/** Capitalised words that are almost never a person name on their own — includes common
 * business/heading vocabulary so document titles and glossary terms aren't mistaken for names. */
export const NAME_STOPWORDS = new Set(
  [
    "the","a","an","and","or","but","if","then","this","that","these","those","here","there","of","to","for","in","on","at","by","with","as","is","are","was","were","be","been",
    "i","we","you","he","she","it","they","my","our","your","his","her","their","its",
    "monday","tuesday","wednesday","thursday","friday","saturday","sunday",
    "january","february","march","april","may","june","july","august","september","october","november","december",
    "please","thanks","thank","hello","hi","hey","dear","regards","best","sincerely","kind","yours",
    "mr","mrs","ms","dr","prof","sir","madam","miss","mx",
    // business / document / heading vocabulary (frequent Title-Case false positives)
    "project","invoice","ticket","account","server","company","team","support","reset","repeat","code","ref","reference",
    "client","customer","patient","user","contact","member","employee","staff","name","email","mobile","phone","call","re",
    "north","south","east","west","street","road","avenue","city","state","floor","court","suite","building","block","unit",
    "standard","bank","system","wallet","tenant","consolidation","consolidated","configuration","glossary","introduction",
    "document","history","version","draft","details","description","item","overview","summary","scope","background","purpose",
    "requirement","requirements","solution","platform","gateway","payment","processing","product","service","services","module",
    "table","figure","section","chapter","appendix","page","note","status","date","type","title","role","department","division",
    "manager","director","officer","analyst","engineer","developer","consultant","specialist","administrator","lead","head",
    // role / signatory / form-field words (column headers, never first names)
    "approver","approval","signatory","signatories","signature","signed","reviewer","authoriser","authorizer","author","applicant",
    "witness","guarantor","recipient","sender","respondent","claimant","designation","position","occupation","nationality","gender",
    "initials","dob","title","salutation","prepared","reviewed","approved","authorised","authorized","completed","submitted","received",
    "policy","procedure","process","report","request","response","approval","review","update","change","release","phase","step",
    "data","field","value","record","entry","report","test","testing","acceptance","production","development","staging","default",
    "corporation","limited","ltd","inc","llc","group","holdings","enterprise","enterprises","international","global","africa","south",
    "claude","anthropic","google","amazon","microsoft","apple","openai","meta","eclipse",
    // Vendors and products, because their NAMES are frequently real surnames and the pair reads as
    // a person: "Oracle Java", "Apache Kafka", "Atlassian Jira". The company word is the only half
    // that gives it away, so it is the half listed here. Measured against 104 tech and product
    // terms, ten of which are Census surnames.
    "oracle","apache","atlassian","adobe","cisco","intel","nvidia","salesforce","sap","ibm","dell",
    "sony","samsung","huawei","tesla","uber","netflix","spotify","github","gitlab","docker","redis",
    "mongodb","elastic","databricks","snowflake","stripe","twilio","atlas","azure","aws","oauth",

  ].map((s) => s.toLowerCase())
);

/**
 * The generated lists, and how they are searched.
 *
 * FIRST_NAMES above is 851 hand-curated entries and it is not going anywhere: it holds African
 * given names no public corpus has, and words like "mark", "will" and "rose" that the generator's
 * filter deliberately throws away. It is an allowlist that always wins.
 *
 * What it could not do is scale. On forty realistic full names written as bare prose it anchored
 * three: Irish, Welsh, Scandinavian, Dutch, Polish and most British names were absent, so whether
 * PII Shield masked somebody depended on whether they happened to be called Jennifer.
 *
 * The generated lists are 18,888 given names and 77,795 surnames (see scripts/build-gazetteer.mjs
 * for their provenance and every exclusion rule). They are kept as sorted newline-delimited STRINGS
 * and searched by bisection rather than loaded into a Set. That is not premature cleverness: a Set
 * of 96,000 strings costs about 24MB of heap and 23ms to build, and this engine is loaded into two
 * worlds on every chat page, so it would be 48MB and 46ms of somebody's page load before they typed
 * anything. As string literals it is 738KB, parsed as one token per list, with lookups near a
 * microsecond and no build step at all.
 */
import { GIVEN_BLOB, SURNAME_BLOB, WORD_SURNAME_BLOB } from "./names-data.js";

/**
 * Is `name` one of the lines in a sorted, newline-delimited blob?
 *
 * `lo` is always at a line start and `hi` is always a line start or the end, which is what makes
 * the bisection terminate: the line containing `mid` can never begin before `lo`.
 */
export function inBlob(blob, name) {
  if (!name || !blob) return false;
  let lo = 0, hi = blob.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const start = blob.lastIndexOf("\n", mid) + 1;
    let end = blob.indexOf("\n", start);
    if (end === -1) end = blob.length;
    const line = blob.slice(start, end);
    if (line === name) return true;
    if (line < name) lo = end + 1;
    else if (hi === start) return false;
    else hi = start;
  }
  return false;
}

/**
 * The same name with its apostrophes taken out.
 *
 * The Census writes O'Brien as OBRIEN and O'Riordan as ORIORDAN — 115,385 Americans are the first
 * one — so a lookup that only tries the literal spelling fails on some of the most common Irish
 * surnames there are. Tried second, never first: a name that is in the list as written is answered
 * from the list as written.
 */
const bare = (n) => n.replace(/['’]/g, "");

/** A given name: the curated list first, because it is the one with the exceptions in it. */
export const isGivenName = (n) => !!n && (FIRST_NAMES.has(n) || inBlob(GIVEN_BLOB, n)
  || (/['’]/.test(n) && inBlob(GIVEN_BLOB, bare(n))));

/** A surname. */
export const isSurname = (n) => !!n && (inBlob(SURNAME_BLOB, n)
  || (/['’]/.test(n) && inBlob(SURNAME_BLOB, bare(n))));

/**
 * Words that begin a PLACE, not a person.
 *
 * "Port Louis", "Los Angeles", "San Francisco", "Fort Worth" — the second half of each is a real
 * and common surname, so the surname anchor reads every one of them as somebody's name. There is no
 * signal in the string that separates "Port Louis" from "Xanthe Ridley"; the only thing that does
 * is knowing that "port" and "los" start place names and given names do not.
 *
 * Deliberately small and closed. It guards ONE rule — a run may not be surname-anchored when it
 * starts on one of these — and is not a general stopword list; NAME_STOPWORDS is that, and adding
 * these to it would start trimming the ends off real names.
 */
export const PLACE_PREFIXES = new Set([
  "port", "fort", "mount", "mt", "lake", "cape", "bay", "san", "santa", "sao", "saint", "st",
  "los", "las", "el", "la", "le", "les", "new", "old", "great", "little", "grand", "upper",
  "lower", "high", "long", "big", "river", "valley", "hill", "glen", "loch", "ben", "castle",
  "kings", "queens", "bishops", "abbey", "church", "market", "camp", "fair", "green", "white",
  "black", "red", "blue", "silver", "golden", "royal", "central", "greater", "outer", "inner",
]);

/**
 * A surname that is also an ordinary English word — Hill, Baker, Wood, Price.
 *
 * Real names, and "John Hill" must mask. But a surname like this may not anchor a name on its own,
 * or "Notting Hill", "Camp Baker" and "Cost Price" become people. 112 entries against 6 measured
 * false positives in 40 place and product names.
 */
export const isWordSurname = (n) => inBlob(WORD_SURNAME_BLOB, n);
