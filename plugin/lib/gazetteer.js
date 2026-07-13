/**
 * First-name gazetteer + honorifics + stopwords, used to anchor heuristic PERSON
 * detection so free-text names get caught WITHOUT flagging every Title-Case phrase
 * (headings, product names, glossary terms) — zero-dep, no ML.
 * Global + African-market-aware. Not exhaustive — clients extend with custom terms,
 * and labelled names ("Name: …", "signed by …") are caught separately.
 */

export const FIRST_NAMES = new Set(
  [
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
  ].map((s) => s.toLowerCase())
);
