/* الدليل الحاسم — بيانات البطاقات
   كل بطاقة وكل خيار في بطاقات المشهد يحمل "صفات" مشتركة (tags).
   هذه الصفات هي ما يربط إشارات الطبيب الشرعي بالأدوات والأدلة. */
'use strict';

const TAG_AR = {
  metal:'معدن', wood:'خشب', cloth:'قماش', leather:'جلد', glass:'زجاج', plastic:'بلاستيك', paper:'ورق',
  liquid:'سائل', powder:'مسحوق', food:'طعام', chem:'مواد كيميائية', elec:'كهرباء', stone:'حجر',
  plant:'نبات', animal:'حيوان', water:'ماء', fire:'نار', smoke:'دخان',
  sharp:'حادّ', heavy:'ثقيل', lightw:'خفيف', long:'طويل', round:'مستدير', soft:'ناعم', rough:'خشن',
  hot:'ساخن', cold:'بارد', wet:'مبلّل', fragile:'قابل للكسر', smell:'رائحة', loud:'صوت عالٍ',
  silent:'صامت', tiny:'صغير جداً', small:'صغير', big:'ضخم', shiny:'لامع',
  red:'أحمر', white:'أبيض', black:'أسود', gold:'ذهبي', blue:'أزرق', green:'أخضر', brown:'بنّي', colorful:'ملوّن',
  kitchen:'المطبخ', drink:'مشروبات', medical:'الطب', sport:'الرياضة', farm:'الزراعة', office:'العمل المكتبي',
  school:'المدرسة', beauty:'الزينة', tech:'التقنية', kids:'الأطفال', tools:'العُدّة', travel:'السفر',
  clothing:'الملابس', music:'الموسيقى', money:'المال', car:'السيارات', home:'البيت', sea:'البحر',
  outdoor:'الخلاء', weapon:'سلاح', games:'الألعاب',
  old:'قديم', modern:'حديث', cheap:'رخيص', expensive:'ثمين', personal:'شخصي', daily:'يومي', hidden:'مخفيّ',
  traditional:'تراثي', dark:'ظلام', bright:'ضوء', fast:'سريع', slow:'بطيء',
  suffocate:'اختناق', bleed:'نزيف', blunt:'ضرب', poison:'سمّ', burn:'حرق', accident:'حادث'
};

function parseDeck(txt, prefix) {
  return txt.trim().split('\n').map((line, i) => {
    const [n, t] = line.split('|');
    return { id: prefix + i, n: n.trim(), tags: t.trim().split(/\s+/) };
  });
}

const MEANS = parseDeck(`
خنجر|metal sharp bleed weapon small shiny traditional
سكين مطبخ|metal sharp bleed kitchen daily
ساطور|metal sharp heavy bleed kitchen
مقص|metal sharp bleed small office beauty
شفرة حلاقة|metal sharp tiny bleed beauty
زجاجة مكسورة|glass sharp fragile bleed drink
إبرة خياطة|metal tiny sharp clothing
حقنة|plastic medical tiny poison liquid
سمّ فئران|powder chem poison home cheap
مبيد حشري|chem liquid poison farm smell
حبوب منوّمة|medical poison white tiny silent
قهوة مسمومة|drink liquid poison hot traditional brown
حبل|cloth long suffocate tools rough
وشاح حرير|cloth soft suffocate clothing beauty colorful
ربطة عنق|cloth suffocate clothing office long
وسادة|cloth soft suffocate home white silent
كيس بلاستيك|plastic suffocate lightw cheap daily
سلسلة حديد|metal long heavy suffocate tools
شريط لاصق|plastic suffocate office tools
حزام جلد|leather long suffocate clothing brown
مطرقة|metal wood heavy blunt tools
مفتاح ربط|metal heavy blunt tools car
عصا خشبية|wood long blunt traditional brown
مضرب|wood long blunt sport
حجر|stone heavy blunt outdoor rough
طوبة|stone heavy blunt tools red rough
إبريق نحاس|metal heavy blunt traditional gold kitchen
تمثال صغير|stone heavy blunt home expensive old
دمبل حديد|metal heavy blunt sport
كرسي|wood heavy big blunt home
مقلاة|metal heavy blunt kitchen black hot
مسدس|metal weapon loud bleed black fast
بندقية صيد|metal wood weapon loud long bleed outdoor
قوس وسهم|wood sharp long weapon sport traditional bleed
ولّاعة|fire burn plastic small smoke
بنزين|liquid fire burn car smell chem
مكواة|elec hot burn home metal clothing
سلك كهرباء|elec burn long tools metal
مجفف شعر|elec burn beauty hot plastic
ماء مغلي|water liquid hot burn kitchen
شمعة|fire burn home bright
حمض الأسيد|chem liquid burn smell
سيارة|car metal big heavy accident fast
دراجة نارية|car metal fast accident loud
سلّم|metal long accident tools
قشرة موز|food accident plant cheap gold
إغراق في الماء|water wet suffocate sea
دفع من مكان مرتفع|accident outdoor fast
أفعى|animal poison outdoor silent
عقرب|animal poison tiny black outdoor
كلب شرس|animal bleed outdoor loud
فطر سام|plant poison food brown
نبتة سامة|plant poison green outdoor
تمر مسموم|food poison brown traditional
كعكة مسمومة|food poison kitchen colorful kids
تسرّب غاز|chem suffocate silent home smell
دخان كثيف|smoke suffocate fire black
مسمار|metal sharp tiny tools
مفك براغي|metal sharp tools small
فأس|metal wood sharp heavy farm bleed
منجل|metal sharp farm bleed
سيخ شواء|metal sharp long kitchen hot
مظلة|cloth metal long blunt daily
زجاجة عطر ثقيلة|glass heavy blunt beauty smell expensive
هاتف محمول|tech elec small blunt modern
عود موسيقي|wood music blunt traditional
قلم حبر|plastic sharp office school small
حقيبة ثقيلة|leather heavy blunt travel
صاعق كهربائي|elec burn weapon modern
جرعة دواء زائدة|medical poison tiny white
حبس في ثلاجة|cold suffocate kitchen elec big
كيس رمل|cloth heavy blunt powder outdoor
مزهرية|glass fragile blunt home colorful
عصا غولف|metal long blunt sport expensive
مشرط جراحي|metal sharp tiny medical bleed shiny
مصيدة حيوانات|metal sharp farm outdoor animal
عصير مسموم|drink liquid poison colorful
ثريا ساقطة|glass heavy accident home bright expensive
`, 'm');

const CLUES = parseDeck(`
خاتم ذهب|metal gold shiny expensive personal small beauty round
ساعة يد|metal tech personal small round shiny
نظارة شمسية|glass plastic black travel beauty
محفظة جلد|leather money personal brown
مفاتيح سيارة|metal car small daily
هاتف مكسور|tech fragile glass modern
شاحن هاتف|elec tech long plastic white
سماعات أذن|tech music small white modern
فنجان قهوة|drink traditional kitchen small hot
دلّة|metal drink traditional gold hot
كوب شاي|glass drink hot fragile
علبة سجائر|paper smoke cheap small
أرجيلة|glass smoke traditional colorful
مسبحة|round small traditional personal colorful
عقال|cloth black traditional clothing round
شماغ|cloth red clothing traditional white
عباءة|cloth black clothing long traditional
حذاء رياضي|clothing sport rough white
حذاء بكعب عالٍ|clothing beauty red expensive
قبعة|cloth clothing outdoor
جوارب|cloth clothing soft daily
قفازات|leather clothing hidden
زر قميص|plastic tiny clothing round
ربطة شعر|cloth beauty kids colorful tiny
أحمر شفاه|beauty red small
زجاجة عطر|glass smell beauty expensive
مرآة صغيرة|glass beauty fragile shiny
مشط|plastic beauty small
فرشاة أسنان|plastic home daily small
منشفة|cloth wet soft home white
صابونة|wet smell home white
علبة دواء|medical small white
ضمادة|cloth medical white
ميزان حرارة|medical glass tiny
كمامة|cloth medical white lightw
تقرير طبي|paper medical white
جواز سفر|paper travel personal
تذكرة طيران|paper travel
حقيبة سفر|leather travel big
خريطة|paper travel colorful old
بوصلة|metal travel round old
كاميرا|tech travel black
صورة قديمة|paper old personal
رسالة حب|paper personal hidden red
دفتر مذكرات|paper personal hidden
مفتاح قديم|metal old small hidden
قفل|metal hidden tools
جهاز تحكم|plastic tech home black
حاسوب محمول|tech office modern elec
ذاكرة USB|tech tiny hidden modern
ورقة عليها كلمة سر|paper hidden tech
فاتورة|paper money daily
شيك بنكي|paper money expensive
عملات معدنية|metal money round small
أوراق نقدية|paper money green
بطاقة بنكية|plastic money personal small
سبيكة ذهب|metal gold heavy expensive shiny
ألماسة|stone tiny shiny expensive white
عقد لؤلؤ|round white sea expensive beauty
صدفة بحرية|sea white fragile
رمل|powder outdoor brown sea
حصى|stone small outdoor rough
ورقة شجر|plant green lightw outdoor
وردة حمراء|plant red smell beauty
بذور|plant tiny farm
تمر|food brown traditional
خبز|food kitchen daily brown
بيض|food fragile white kitchen
ليمون|food gold kitchen
بهارات|food powder smell kitchen red
ملح|powder white kitchen
سكّر|powder white food
عسل|food liquid gold
حليب|drink liquid white
عصير|drink liquid colorful
علبة مشروب غازي|metal drink cheap colorful
زجاجة ماء|plastic water drink
مكعبات ثلج|water cold white
شوكولاتة|food brown kids
علكة|food kids tiny
بالون|plastic kids colorful lightw
دمية|kids cloth soft
سيارة لعبة|kids car plastic small
كرة قدم|sport round
صافرة|sport loud metal small
ميدالية|metal gold sport round
ورق لعب|paper games
نرد|games small plastic white
رقعة شطرنج|games wood black white
طاولة زهر|games wood traditional
جهاز ألعاب|games tech modern
ناي|wood music long traditional
طبلة|music loud traditional
مكبر صوت|music elec loud
كتاب|paper school old
قلم رصاص|wood school small
ممحاة|school tiny plastic
مسطرة|plastic school long
حقيبة مدرسية|kids school cloth
دفتر تلوين|paper school colorful kids
طباشير|powder white school
دبّاسة|metal office small
مشبك ورق|metal office tiny
ختم رسمي|office personal red
ملف أوراق|paper office
بطاقة عمل|paper office personal small
بطاقة موظف|plastic office personal
شريط قياس|metal tools long
برغي|metal tiny tools
خوذة عمل|plastic tools gold
علبة طلاء|liquid colorful tools smell chem
غراء|chem liquid tools
زيت محرك|liquid black car smell
إطار سيارة|car rough black round
لوحة سيارة|metal car
فانوس|metal bright traditional old
مصباح يدوي|bright tools elec
عود ثقاب|wood fire tiny
رماد|powder black fire smoke
بخور|smell smoke traditional wood
مبخرة|metal smoke traditional gold
ريشة|animal lightw white soft
شعر قطة|animal tiny soft
طوق كلب|animal leather
عظمة|animal white old
بقعة حبر|liquid black office
لاصق جروح|medical tiny plastic
عكاز|wood medical long old
نظارة طبية|glass medical personal
سنّ مخلوع|white tiny medical
ظرف مختوم|paper hidden office
منديل|paper white soft daily
مروحة يدوية|lightw traditional beauty
ساعة رملية|glass old powder slow
تقويم|paper office daily
رسالة تهديد|paper hidden red
جريدة|paper daily old
عدسة مكبرة|glass round tools
بكرة خيط|cloth tiny clothing colorful
صنارة صيد|sea long outdoor sport
شبكة صيد|sea long rough
مرساة|metal heavy sea
خيمة|cloth outdoor travel big
فحم|black fire powder stone
قِدر كبير|metal kitchen big hot
ملعقة|metal kitchen small shiny
صحن مكسور|fragile kitchen white
فرشاة رسم|wood colorful
سجادة|cloth big traditional colorful home
ستارة|cloth long home
بطانية|cloth soft home big
جرس الباب|elec home loud
كاميرا مراقبة|tech hidden modern elec
تذكرة حفلة|paper music
بطاقة دعوة عرس|paper personal colorful music
مسواك|wood traditional tiny
كحل|beauty black traditional tiny
حنّاء|plant powder beauty traditional brown
شعر مستعار|beauty hidden
سوار|metal beauty round shiny
قلادة|metal gold beauty expensive
علبة مكياج|beauty colorful
مظروف نقود|paper money hidden
كأس بطولة|metal gold sport shiny
ساعة حائط|round home old
مفتاح غرفة فندق|plastic travel small
إيصال صرّاف|paper money daily
بطارية|elec small chem
جوال قديم|tech old elec
`, 'c');

function T(id, kind, title, opts) {
  return { id, kind, title, o: opts.map(x => { const [n, t] = x.split('|'); return { n, tags: t.split(' ') }; }) };
}

const CAUSE = T('C', 'cause', 'سبب الوفاة', [
  'اختناق|suffocate silent', 'نزيف حاد|bleed sharp red', 'ضربة قاتلة|blunt heavy',
  'تسمّم|poison chem', 'حرق أو صعق|burn fire elec hot', 'حادث مأساوي|accident fast car']);

const LOCS = [
  T('L1', 'loc', 'في البيت', ['غرفة النوم|personal soft clothing home', 'المطبخ|kitchen food hot drink', 'الحمّام|wet water beauty medical', 'المجلس|traditional drink home games', 'السطح|outdoor accident bright', 'المخزن|tools old hidden dark']),
  T('L2', 'loc', 'في المدينة', ['السوق الشعبي|traditional food money cloth', 'المقهى|drink smoke games', 'المستشفى|medical white', 'موقف السيارات|car metal', 'محل المجوهرات|gold expensive shiny beauty', 'الشارع المزدحم|loud fast daily']),
  T('L3', 'loc', 'في البرّ', ['الصحراء|hot outdoor powder travel', 'المزرعة|farm animal plant', 'الشاطئ|sea water wet', 'الوادي|stone outdoor accident', 'البئر|water dark old', 'البستان|plant green outdoor']),
  T('L4', 'loc', 'في مكان العمل', ['المدرسة|school kids paper', 'المكتب|office paper tech', 'الورشة|tools metal chem loud', 'النادي الرياضي|sport', 'الفندق|travel expensive', 'المطار|travel modern'])
];

const SCENES = [
  T('S1', 'scene', 'المادة الغالبة', ['معدن|metal', 'خشب|wood', 'قماش أو جلد|cloth leather', 'زجاج أو بلاستيك|glass plastic', 'ورق|paper', 'سائل أو مسحوق|liquid powder water']),
  T('S2', 'scene', 'اللون اللافت', ['أحمر|red', 'أبيض|white', 'أسود|black', 'ذهبي أو أصفر|gold', 'بنّي|brown', 'ألوان زاهية|colorful blue green']),
  T('S3', 'scene', 'الحجم', ['أصغر من الإصبع|tiny', 'في راحة اليد|small', 'طويل|long', 'ثقيل|heavy', 'خفيف كالريشة|lightw', 'ضخم|big']),
  T('S4', 'scene', 'الملمس', ['حادّ|sharp', 'ناعم|soft', 'خشن|rough stone', 'ساخن|hot fire', 'بارد|cold metal', 'مبلّل|wet water liquid']),
  T('S5', 'scene', 'مجال الاستعمال', ['المطبخ والطعام|kitchen food drink', 'الطب والصحة|medical', 'الرياضة واللعب|sport games kids', 'العمل والدراسة|office school', 'الزينة واللباس|beauty clothing', 'العُدّة والسيارات|tools car']),
  T('S6', 'scene', 'حالة الجثة', ['ما زالت دافئة|hot fast', 'باردة متصلّبة|cold slow', 'ملطّخة|red liquid bleed', 'مبلّلة|wet water sea', 'مغطاة بالغبار|powder old outdoor', 'سليمة بلا أثر|poison suffocate silent']),
  T('S7', 'scene', 'أثر على الجسد', ['جرح عميق|sharp bleed', 'كدمات|blunt heavy', 'حروق|burn fire hot', 'علامات حول الرقبة|suffocate long cloth', 'ثقب صغير|tiny medical sharp', 'لا أثر ظاهر|poison silent hidden']),
  T('S8', 'scene', 'ما تركه الجاني', ['بصمات|glass personal', 'رائحة غريبة|smell chem', 'بقع|liquid red food', 'خيوط أو شعر|cloth animal beauty', 'أوراق مبعثرة|paper office', 'آثار أقدام|clothing outdoor powder']),
  T('S9', 'scene', 'وقت الجريمة', ['الفجر|sport travel cold', 'وقت الدوام|office school', 'وقت الغداء|kitchen food', 'السهرة|games music drink', 'منتصف الليل|dark hidden black', 'غير معروف|old slow']),
  T('S10', 'scene', 'الطقس', ['حرّ شديد|hot', 'مطر|wet water', 'عاصفة رملية|powder stone outdoor', 'برد قارس|cold', 'رياح قوية|lightw outdoor', 'صحو هادئ|bright daily']),
  T('S11', 'scene', 'الدافع', ['المال|money expensive', 'الحب والغيرة|beauty personal red', 'الانتقام|old weapon', 'إخفاء سرّ|hidden paper', 'صدفة سيئة|accident daily', 'المنافسة|sport office']),
  T('S12', 'scene', 'الانطباع العام', ['فوضى|loud fragile', 'تخطيط دقيق|tech medical slow', 'عنف|heavy sharp blunt', 'هدوء مريب|silent poison soft', 'غرابة|chem animal', 'عادي جداً|daily cheap']),
  T('S13', 'scene', 'الصوت المسموع', ['صرخة|sharp bleed', 'ارتطام|heavy blunt', 'تحطّم|glass fragile', 'دويّ|loud weapon fire', 'موسيقى|music tech', 'صمت تام|silent']),
  T('S14', 'scene', 'ما لاحظه الجيران', ['سيارة مسرعة|car fast', 'رائحة|smell smoke', 'ضوء أو نار|fire bright', 'زائر غريب|travel hidden', 'حيوان|animal', 'لا شيء|silent hidden']),
  T('S15', 'scene', 'مهنة الضحية', ['طبيب|medical', 'طبّاخ|kitchen food', 'مزارع أو عامل|farm tools', 'تاجر|money gold', 'معلّم أو موظف|school office paper', 'رياضي أو فنان|sport music beauty']),
  T('S16', 'scene', 'علاقة الضحية بالجاني', ['من العائلة|home personal', 'صديق قديم|old games', 'زميل عمل|office tools', 'جار|home daily', 'غريب|travel', 'منافس|sport money']),
  T('S17', 'scene', 'ملابس الضحية', ['أنيقة|expensive beauty', 'رياضية|sport', 'ملابس عمل|tools office', 'تراثية|traditional', 'ملابس نوم|soft home', 'ممزّقة|sharp rough']),
  T('S18', 'scene', 'مدة الجريمة', ['لحظة|fast weapon elec', 'دقائق|suffocate blunt', 'ساعات|poison slow', 'أيام|old food', 'خُطط لها شهوراً|hidden paper tech', 'لا يُعرف|silent']),
  T('S19', 'scene', 'قيمة الأداة', ['تحفة قديمة|old traditional', 'حديثة|modern tech', 'ثمينة|expensive gold shiny', 'رخيصة|cheap daily', 'ذكرى شخصية|personal', 'تُرمى بعد الاستعمال|paper plastic food']),
  T('S20', 'scene', 'تفصيل غريب', ['الأضواء مطفأة|dark elec', 'النافذة مفتوحة|outdoor lightw', 'ساعة متوقفة|tech metal round', 'طعام لم يُؤكل|food kitchen poison', 'الهاتف مفقود|tech modern', 'باب مكسور|heavy tools']),
  T('S21', 'scene', 'مكان الأداة الآن', ['مخبّأة|hidden', 'في الماء|water sea', 'محروقة|fire smoke', 'بجانب الضحية|personal', 'في سيارة|car', 'اختفت تماماً|tiny lightw']),
  T('S22', 'scene', 'الرائحة', ['عطر|beauty smell', 'دخان|smoke fire', 'طعام|food kitchen', 'مواد كيميائية|chem', 'رائحة البحر|sea', 'بلا رائحة|metal plastic']),
  T('S23', 'scene', 'أيام الضحية الأخيرة', ['كانت مريضة|medical', 'سافرت|travel', 'خسرت مالاً|money', 'تشاجرت مع أحد|weapon loud', 'بدأت هواية جديدة|sport music games', 'كانت تخفي شيئاً|hidden'])
];

const CARD = {};
[...MEANS, ...CLUES].forEach(c => { CARD[c.id] = c; });
const TILE = {};
[CAUSE, ...LOCS, ...SCENES].forEach(t => { TILE[t.id] = t; });

// فحص سلامة البيانات أثناء التطوير
(function validate() {
  const bad = [];
  [...MEANS, ...CLUES].forEach(c => c.tags.forEach(t => { if (!TAG_AR[t]) bad.push(c.n + ':' + t); }));
  Object.values(TILE).forEach(t => t.o.forEach(o => o.tags.forEach(g => { if (!TAG_AR[g]) bad.push(t.title + ':' + g); })));
  if (bad.length) console.warn('صفات غير معروفة:', bad);
})();
