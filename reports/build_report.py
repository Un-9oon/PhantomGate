from pathlib import Path
import argparse
import re, json, html, math, zipfile
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(); ap.add_argument('--output-dir',default=str(ROOT/'outputs')); args=ap.parse_args()
OUT=Path(args.output_dir).resolve(); OUT.mkdir(parents=True,exist_ok=True)
DIAG=OUT/'diagrams'; DIAG.mkdir(exist_ok=True)
NAVY='#142D45'; BLUE='#176B91'; PALE='#EDF4F7'; GRAY='#52616D'; ORANGE='#A75228'
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='BodyF',fontName='Times-Roman',fontSize=11.5,leading=16,alignment=TA_JUSTIFY,spaceAfter=9))
styles.add(ParagraphStyle(name='H1F',fontName='Helvetica-Bold',fontSize=19,leading=24,textColor=colors.HexColor(NAVY),spaceAfter=17))
styles.add(ParagraphStyle(name='H2F',fontName='Helvetica-Bold',fontSize=12,leading=16,textColor=colors.HexColor(BLUE),spaceBefore=9,spaceAfter=7))
styles.add(ParagraphStyle(name='SmallF',fontName='Helvetica',fontSize=8.5,leading=12,spaceAfter=7))
styles.add(ParagraphStyle(name='CellF',fontName='Helvetica',fontSize=8.3,leading=11))
styles.add(ParagraphStyle(name='CaptionF',fontName='Helvetica',fontSize=9,leading=12,textColor=colors.HexColor(GRAY),spaceBefore=7,spaceAfter=12))
styles.add(ParagraphStyle(name='CoverF',fontName='Helvetica-Bold',fontSize=34,leading=40,textColor=colors.HexColor(NAVY),spaceAfter=18))
styles.add(ParagraphStyle(name='SubF',fontName='Helvetica',fontSize=17,leading=24,textColor=colors.HexColor(BLUE),spaceAfter=18))
W=453
pages=[]; figs=[]; tabs=[]; md=[]
def para(t,sty='BodyF'): return Paragraph(t,styles[sty])
def table(headers,rows,widths=None):
    hs=ParagraphStyle('TableHeadF',parent=styles['CellF'],textColor=colors.white,fontName='Helvetica-Bold')
    data=[[Paragraph(html.escape(str(x)),hs) for x in headers]]+[[para(html.escape(str(x)),'CellF') for x in row] for row in rows]
    t=Table(data,colWidths=widths or [W/len(headers)]*len(headers),repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor(NAVY)),('TEXTCOLOR',(0,0),(-1,0),colors.white),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor(PALE),colors.white]),('LINEBELOW',(0,0),(-1,0),0.6,colors.HexColor(BLUE)),('LINEBELOW',(0,1),(-1,-1),0.3,colors.HexColor('#D7E0E5'))]))
    return t

ROUTES={
 'figure-4-2':{('s','l'):[(310,170),(345,170)],('l','s'):[(345,140),(310,140)],('r','s'):[(200,255),(200,195)],('s','r'):[(255,195),(255,255)]},
 'figure-4-3':{('p4','p2'):[(171,100),(140,100),(140,305),(171,305)]},
 'figure-4-7':{('e','c'):[(300,17),(316,17),(316,157),(300,157)]},
 'figure-4-11':{('ctrl','lab'):[(68,210),(68,233),(385,233),(385,210)]},
 'figure-4-12':{('valid','failed'):[(164,285),(148,285),(148,60),(164,60)]}
}

class Diagram(Flowable):
    def __init__(self,key,title,nodes,edges,h=310,notes=None):
        Flowable.__init__(self); self.width=W; self.height=h; self.key=key; self.nodes=nodes; self.edges=edges; self.title=title; self.notes=notes or []
        self.svg()
    def route(self,a,b,n):
        if (a,b) in ROUTES.get(self.key,{}): return ROUTES[self.key][(a,b)]
        x,y,xx,yy=self.points(n[a],n[b]);return [(x,y),(xx,yy)]
    def label_point(self,pts):
        segments=list(zip(pts,pts[1:]));p,q=max(segments,key=lambda pq:(pq[0][0]-pq[1][0])**2+(pq[0][1]-pq[1][1])**2)
        return (p[0]+q[0])/2,(p[1]+q[1])/2
    def svg(self):
        h=self.height; n={x[0]:x for x in self.nodes}; s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}"><rect width="100%" height="100%" fill="white"/><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="{BLUE}"/></marker></defs>']
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n)
            s.append('<polyline points="'+' '.join(f'{x},{h-y}' for x,y in pts)+f'" fill="none" stroke="{BLUE}" stroke-width="1.1" marker-end="url(#arrow)"/>')
            if label:
                mx,my=self.label_point(pts);my=h-my;sw=max(22,len(label)*4.4)
                s.append(f'<rect x="{mx-sw/2}" y="{my-9}" width="{sw}" height="12" fill="white"/><text x="{mx}" y="{my}" text-anchor="middle" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(label)}</text>')
        for _,x,y,w,hh,label,*kind in self.nodes:
            k=kind[0] if kind else 'box'; fill=PALE if k!='actor' else '#FFF5ED'; rx=hh/2 if k=='process' else 4
            s.append(f'<rect x="{x}" y="{h-y-hh}" width="{w}" height="{hh}" rx="{rx}" fill="{fill}" stroke="{BLUE}"/>')
            lines=label.split('\n'); yy=h-(y+hh/2)+(len(lines)-1)*-5.7
            for i,line in enumerate(lines): s.append(f'<text x="{x+w/2}" y="{yy+i*11.4+3}" text-anchor="middle" font-family="Arial" font-size="8.4" fill="{NAVY}">{html.escape(line)}</text>')
            if k=='store': s.append(f'<line x1="{x+7}" y1="{h-y}" x2="{x+7}" y2="{h-y-hh}" stroke="{BLUE}"/>')
        for x,y,t in self.notes:s.append(f'<text x="{x}" y="{h-y}" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(t)}</text>')
        s.append('</svg>'); (DIAG/(self.key+'.svg')).write_text('\n'.join(s),encoding='utf-8')
    def points(self,p,q):
        _,x,y,w,h,*_=p; _,xx,yy,ww,hh,*_=q; cx,cy=x+w/2,y+h/2; dx,dy=xx+ww/2-cx,yy+hh/2-cy
        if abs(dx)/(w or 1)>abs(dy)/(h or 1):return (x+w if dx>0 else x,cy,xx if dx>0 else xx+ww,yy+hh/2)
        return (cx,y+h if dy>0 else y,xx+ww/2,yy if dy>0 else yy+hh)
    def draw(self):
        c=self.canv; n={x[0]:x for x in self.nodes}
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n);c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(1)
            for (x1,y1),(x2,y2) in zip(pts,pts[1:]):c.line(x1,y1,x2,y2)
            (x1,y1),(x2,y2)=pts[-2:]
            angle=math.atan2(y2-y1,x2-x1); path=c.beginPath();path.moveTo(x2,y2);path.lineTo(x2-6*math.cos(angle-.45),y2-6*math.sin(angle-.45));path.lineTo(x2-6*math.cos(angle+.45),y2-6*math.sin(angle+.45));path.close();c.setFillColor(colors.HexColor(BLUE));c.drawPath(path,fill=1,stroke=0)
            if label:
                c.setFont('Helvetica',7.5);tw=c.stringWidth(label,'Helvetica',7.5);mx,my=self.label_point(pts);c.setFillColor(colors.white);c.rect(mx-tw/2-3,my-2,tw+6,11,fill=1,stroke=0);c.setFillColor(colors.HexColor(GRAY));c.drawCentredString(mx,my+1,label)
        for _,x,y,w,h,label,*kind in self.nodes:
            k=kind[0] if kind else 'box';c.setStrokeColor(colors.HexColor(BLUE));c.setFillColor(colors.HexColor('#FFF5ED' if k=='actor' else PALE));c.roundRect(x,y,w,h,h/2 if k=='process' else 4,fill=1,stroke=1)
            if k=='store':c.line(x+7,y,x+7,y+h)
            lines=label.split('\n');c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica',8.4)
            for i,line in enumerate(lines): c.drawCentredString(x+w/2,y+h/2+(len(lines)-1)*5.7-i*11.4-3,line)
        c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY))
        for x,y,t in self.notes:c.drawString(x,y,t)

def P(title,*blocks):
    pages.append((title,list(blocks)));return len(pages)
def H(t):return ('h',t)
def T(title,headers,rows,widths=None):return ('t',title,headers,rows,widths)
def F(num,title,nodes,edges,h=310,notes=None):return ('f',num,title,nodes,edges,h,notes)
def B(*items):return ('b',items)

P('Title page',('cover',))
P('Declaration and approval',
  'This revised report documents a proposed final-year project combining Penetration Testing and Artificial Intelligence. It distinguishes the existing PhantomGate repository from the new AI-assisted laboratory assessment design. No experimental results, trained-model performance, institutional approval, or production certification are asserted.',
  H('Student declaration'),
  'We declare that the final submission will identify third-party code and literature, document our own contributions, and report experiments accurately. This draft is unsigned and does not constitute a declaration by any named student.',
  T('Administrative details',['Field','To be completed before submission'],[['Student name(s) / registration ID(s)','Not supplied'],['Degree / department / university','Not supplied'],['Supervisor / co-supervisor','Not supplied'],['Academic session / submission date','Not supplied'],['Student signature(s) / date','Unsigned'],['Supervisor / examiner approval','Pending institutional review']],[160,293]),
  H('Formatting and revision note'),
  'Prepared on 21 October 2026 as a conventional A4 FYP design report. The institution has not supplied a template. Apply its required cover, binding margin, declarations, citation style, and approval wording before submission. Acknowledgements should be added by the students after confirming actual contributions.')
P('Abstract',
  'PhantomGate-Lab proposes an AI-assisted penetration-testing agent for controlled authentication-security assessment. The project uses the existing Go-based PhantomGate framework as a laboratory component and adds a separately trained policy that selects from a predefined catalogue of bounded assessment actions. The central research question is whether a learned policy can discover more distinct, independently validated weaknesses than fixed and random test sequences under the same action budget on unseen laboratory configurations.',
  'The proposed system separates model recommendations from execution authorization. A deterministic scope gate checks every action, a laboratory runner interacts with synthetic applications, and an independent verifier produces ground-truth finding labels. Sanitized observations feed the policy; passwords, authentication-token values, scenario identifiers, and hidden vulnerability labels are excluded from model inputs. The initial learning approach is supervised action ranking using expert-labeled states, with logistic regression and gradient-boosted trees as candidate models.',
  'Evaluation will use application-level and scenario-family holdouts, paired experiment seeds, coverage-versus-budget curves, finding precision, decision overhead, and model-abstention measures. Reliability work will address durable storage, immutable snapshots, explicit timeouts, graceful shutdown, bounded resources, auditability, and experiment reproducibility. Proposed outcomes are a testbed, a documented dataset, trained policies, a reproducible evaluation package, and evidence-linked reports. Novelty and robustness remain hypotheses until the literature gap and measured results support them.',
  H('Keywords'),
  'Penetration testing; artificial intelligence; supervised action ranking; authentication assessment; controlled laboratory; generalization; evidence validation.',
  H('Project status'),
  'Design and implementation proposal. This document revises the report only; it does not claim implementation of the proposed AI modules or completion of the evaluation.')
P('Table of contents',('toc',))
P('List of figures, tables and abbreviations',('lists',))

P('1. Introduction',
  H('1.1 Background and motivation'),
  'Authentication assessments require choices about which checks to perform, how to interpret observations, and when evidence is sufficient. A fixed sequence is reproducible but cannot adapt to every observed state. A trained policy may prioritize useful checks, but its advantage must be demonstrated against strong non-learning baselines. Existing AI penetration-testing research already studies planning, tool interaction, and policy learning [1-4].',
  H('1.2 Problem statement'),
  'The existing PhantomGate report describes an interception framework but does not establish an AI training pipeline, an independent finding verifier, or a leakage-resistant benchmark. Broad claims of zero latency, universal MFA bypass, perfect concurrency, and production readiness are unsuitable without supporting evidence. This revision proposes a narrower, measurable academic system.',
  H('1.3 Aim'),
  'Design and evaluate a learned action-selection policy for bounded authentication-security assessments in an isolated laboratory, while retaining independent scope enforcement and finding validation.',
  H('1.4 Research questions'),
  B('RQ1: At the same action budget, does the learned policy identify more distinct validated weaknesses than fixed, random, and heuristic policies?', 'RQ2: How does performance change when the application or configuration family is absent from training?', 'RQ3: What overhead and failure modes arise from uncertainty handling, missing telemetry, and policy-service failure?'),
  H('1.5 Intended audience'),
  'Students, supervisors, and examiners assessing both Penetration Testing and Artificial Intelligence. The system is an experimental assessment agent; its model is not a phishing detector.')
P('1. Introduction - objectives and scope',
  T('Table 1.1 - Objectives and acceptance evidence',['ID','Objective','Acceptance evidence'],[['O1','Build a repeatable laboratory','Three synthetic apps; versioned manifests; reset tests'],['O2','Train our own policy','Dataset card, training code, recorded configuration, model artifact'],['O3','Demonstrate a fair comparison','Fixed, random, and heuristic baselines; equal budgets and observations'],['O4','Validate findings independently','Evidence references and verifier verdict for every reported finding'],['O5','Engineer reliable operation','Recovery, concurrency, scope, redaction, and shutdown test records']],[35,169,249]),
  H('1.6 Included scope'),
  'Lab-owned applications, synthetic accounts, versioned authentication configurations, bounded test-case selection, sanitized telemetry, model training, evidence validation, remediation retests, and academic reporting. The AI chooses registered action identifiers; it does not generate unrestricted commands.',
  H('1.7 Scope boundaries'),
  'External identity providers, real-user credentials, live phishing campaigns, arbitrary target discovery, and autonomous changes to authorization are excluded from the research experiments. Existing network-interception modules are not assumed necessary for the proposed benchmark.',
  H('1.8 Academic contribution'),
  'The candidate contribution is a reproducible authentication-focused action-selection benchmark with independent finding verification and cross-application evaluation. Neither reverse-proxy interception nor the use of AI in penetration testing is claimed as new. A publishable novelty claim requires a broader systematic review and positive or informative negative experimental evidence.')

P('2. Literature review - review method',
  H('2.1 Review scope and source quality'),
  'This is a focused narrative review, checked on 21 October 2026, rather than an exhaustive systematic review. Primary sources include conference papers, author-hosted manuscripts, arXiv records, the Microsoft Research project page, NIST guidance, and the W3C WebAuthn specification. Preprints are identified explicitly; standards and software artifacts are not presented as peer-reviewed research papers.',
  H('2.2 Search and screening approach'),
  'Queries combined automated penetration testing, reinforcement learning, authentication assessment, reverse-proxy phishing, policy generalization, and benchmarks. Sources were included when they directly informed action selection, experimental design, authentication assumptions, or assessment governance. Generic phishing-email classifiers were excluded because the proposed model selects assessment actions rather than classifying messages.',
  H('2.3 Autonomous penetration testing'),
  'Schwartz and Kurniawati [1] study model-free reinforcement learning within a network simulator and report limitations as problem size grows. This establishes simulated policy learning as prior work. Becker et al. [2] compare Q-learning, DQN, and A3C in NASim scenarios. Their preprint supports algorithm comparisons but also makes clear that small simulated environments limit general claims.',
  H('2.4 LLM-assisted assessment'),
  'PentestGPT [3], published at USENIX Security 2024, evaluates LLM capabilities and organizes assessment work into interacting modules to reduce context loss. It demonstrates that AI-assisted testing and task progression are established research areas. PhantomGate-Lab instead proposes a small trained ranking policy with a finite action catalogue, making its decisions easier to budget and reproduce.')
P('2. Literature review - simulation and authentication',
  H('2.5 Simulation and generalization'),
  'CyberBattleSim [4] provides an abstract environment for studying autonomous agents and reinforcement learning. It is a research software toolkit, not evidence that policies transfer automatically to live applications. NASimJax v3 [5], a 2026 preprint revised on 4 October 2026, studies policy learning, environment generation, and out-of-distribution generalization. Therefore, neither unseen-environment evaluation nor diverse scenario generation can be claimed as unique in isolation.',
  H('2.6 Reverse-proxy phishing research'),
  'Catching Transparent Phish [6], presented at ACM CCS 2021, analyzes MITM phishing toolkits and develops detection based on network characteristics. It establishes the underlying interception technique as prior work. This project uses a controlled instance as an experimental component; it does not reproduce the paper\'s detector or claim that arbitrary timing changes establish evasion.',
  H('2.7 Authentication and fallback assumptions'),
  'Ulqinaku et al. [7] investigate social-engineering downgrade from FIDO U2F to alternative authentication methods. The study concerns fallback behavior, not a general cryptographic defeat of FIDO. WebAuthn [9] defines origin- and relying-party-based authentication checks. Laboratory configurations must separate correct WebAuthn behavior from recovery or fallback policy weaknesses.',
  H('2.8 Assessment methodology'),
  'NIST SP 800-115 [8] provides guidance for planning, conducting, analyzing, and reporting security assessments. It informs scope and evidence practices; citing it does not certify this project. The proposed workflow adds machine learning within that assessment lifecycle.')
P('2. Literature review - comparison and research gap',
  T('Table 2.1 - Related-work comparison',['Source','Established contribution','Relationship to this proposal'],[['[1] Schwartz & Kurniawati, 2019','RL policies in a network simulator','AI action selection is prior art; motivates scalable baselines'],['[2] Becker et al., 2024 preprint','RL algorithm comparison in NASim','Motivates equal-budget evaluation and simulation limits'],['[3] PentestGPT, 2024','LLM-assisted assessment and benchmark','Compare task progression; our design uses a finite trained ranker'],['[4] CyberBattleSim, research toolkit','Abstract autonomous-agent environment','Supports repeatability; abstraction limits transfer'],['[5] NASimJax v3, 2026 preprint','Fast simulation and policy generalization','Generalization itself is not a new contribution'],['[6] Kondracki et al., 2021','MITM toolkit analysis and detection','Provides authentication-threat context, not an action policy'],['[7] Ulqinaku et al., 2021','FIDO fallback/downgrade user study','Distinguishes recovery weaknesses from protocol guarantees']],[112,158,183]),
  H('2.9 Candidate gap and falsification'),
  'The proposed study narrows to evidence-verified authentication assessment: compare small trained action policies across held-out synthetic applications while controlling observations and action budgets. This combination is a candidate gap in the sources reviewed, not a demonstrated first. A follow-up review must check authentication-specific benchmarks and recent agent systems. If comparable work exists, position this as a replication, benchmark extension, or reliability study.',
  'A null result is acceptable: if the heuristic equals or outperforms the trained model on held-out apps, report that outcome rather than changing test splits or claiming universal superiority.')

P('3. Requirements engineering',
  H('3.1 Stakeholders and operational assumptions'),
  'The student operator configures assessments; the supervisor approves the laboratory scope; the researcher curates datasets and trains models; the examiner reviews evidence and reproducibility. All experiments use provisioned applications with synthetic accounts. Host and network isolation are prerequisites, not responsibilities delegated to the model.',
  T('Table 3.1 - Functional requirements',['ID','Requirement','Verification'],[['FR01','Load a versioned scope and scenario manifest','Reject incomplete or invalid manifests'],['FR02','Select only registered assessment actions','Reject unknown IDs and invalid arguments'],['FR03','Enforce scope and budget before execution','Scope and exhaustion integration tests'],['FR04','Capture redacted observations with evidence IDs','Schema and secret-canary tests'],['FR05','Train and load a versioned ranking model','Training replay and artifact compatibility checks'],['FR06','Validate and deduplicate findings independently','Known-positive and known-negative fixtures'],['FR07','Support stop, cleanup, reset, and retest','Interruption and reset-equivalence tests'],['FR08','Export an evidence-linked report','Every finding resolves to a verifier record']],[43,260,150]),
  H('3.2 Interfaces'),
  'The policy interface accepts a sanitized state and permitted-action list. It returns ranked action IDs, confidence, and a structured reason code. The runner accepts only validated actions. The verifier has separate access to lab ground truth; its hidden scenario facts never enter policy features.')
P('3. Requirements - quality and traceability',
  T('Table 3.2 - Non-functional requirements (proposed targets)',['ID','Requirement / target','Acceptance evidence'],[['NFR01','Zero out-of-scope executions in negative tests','Gate audit records and network-denial evidence'],['NFR02','Zero seeded secret values in exported telemetry','Automated canary scans of dataset and report'],['NFR03','No corrupted committed records after interruption','Crash-injection and recovery tests'],['NFR04','No detected races in supported execution paths','Race-check logs plus concurrent reader/writer tests'],['NFR05','Local model p95 decision time <= 250 ms','Measured hardware and load documented'],['NFR06','Cleanup completes within 10 s of stop request','Fault and cancellation integration tests'],['NFR07','All reported findings have verifier evidence','Foreign-key checks and report validation']],[44,221,188]),
  'These are initial acceptance targets, not measured achievements. Revise them with the supervisor before final testing and record any changes before inspecting the final holdout.',
  H('3.3 Requirements traceability'),
  'O1 maps to FR01, FR07, NFR03 and NFR06; O2 maps to FR04-FR05 and NFR02; O3 maps to FR03 and the evaluation protocol; O4 maps to FR06-FR08 and NFR07; O5 maps to NFR01-NFR06. Appendix A provides the validation matrix.',
  H('3.4 Feasibility'),
  'A CPU workstation can support the initial tabular models and small lab applications. Record actual CPU, RAM, OS, dependency versions, and runtime measurements. A GPU and large language model are optional extensions rather than prerequisites.')

P('4. System design - architecture',
  F('4.1','Proposed component architecture',[
  ('op',10,260,120,45,'Operator / supervisor\nScope and run configuration','actor'),('pol',167,260,120,45,'Trained policy\nRank permitted actions'),('reg',324,260,120,45,'Model registry\nVersion + schema','store'),
  ('orc',10,155,120,50,'Assessment orchestrator\nState + action budget'),('gate',167,155,120,50,'Deterministic scope gate\nAuthorize every action'),('run',324,155,120,50,'Bounded lab runner\nRegistered adapters'),
  ('obs',10,40,120,50,'Telemetry sanitizer\nObservation features'),('ver',167,40,120,50,'Independent verifier\nGround-truth verdict'),('lab',324,40,120,50,'Isolated synthetic apps\nPhantomGate lab adapter')],
  [('op','orc','configure'),('orc','pol','state'),('reg','pol','model'),('pol','gate','action ID'),('orc','gate','scope + budget'),('gate','run','permitted'),('run','lab','lab check'),('lab','ver','server evidence'),('ver','obs','verdict ID'),('obs','orc','redacted result')],h=325),
  H('4.1 Separation of authority'),
  'The trained policy recommends an action. The deterministic gate decides whether it may execute. The verifier decides whether evidence supports a finding. These roles remain distinct to prevent a plausible model output from becoming authorization or ground truth.',
  H('4.2 Existing and proposed components'),
  'Existing Go packages provide the repository foundation. The orchestrator, scope gate, ML registry, sanitized dataset pipeline, and independent verifier shown here are proposed additions. No executable offensive capability is added by this report revision.')
P('4. System design - context DFD',
  F('4.2','Context diagram: system boundary',[
  ('s',145,120,165,75,'0. PhantomGate-Lab\nBounded AI-assisted\nauthentication assessment','process'),('o',0,135,110,50,'Operator / supervisor','actor'),('l',345,135,108,50,'Synthetic lab apps','actor'),('r',145,255,165,45,'Researcher / model curator','actor'),('e',145,10,165,45,'Examiner / reviewer','actor')],
  [('o','s','scope + run request'),('s','l','permitted checks'),('l','s','sanitized observations'),('r','s','versioned model'),('s','r','redacted dataset'),('s','e','report + evidence')],h=320),
  H('4.3 DFD conventions'),
  'This report uses a context diagram with process 0, followed by Level 1 processes 1.0-5.0 and a Level 2 decomposition of process 3.0. Rounded nodes denote processes, tinted rectangles denote external entities, and marked rectangles denote data stores. Arrows carry data rather than execution order.',
  'The boundary includes assessment coordination and evidence handling. The lab applications and researcher are external entities. No direct external-to-store flow is permitted; data passes through a validating process.')
P('4. System design - DFD Level 1',
  F('4.3','DFD Level 1: assessment and evidence flows',[
  ('o',0,285,110,40,'Operator','actor'),('r',0,365,110,40,'Researcher','actor'),('p1',0,200,110,50,'1.0 Validate scope\nand initialize run','process'),('d1',0,95,110,48,'D1 Run manifest\nScope + budget','store'),
  ('p2',171,285,110,40,'2.0 Rank actions','process'),('p3',171,180,110,50,'3.0 Authorize and\nexecute lab check','process'),('lab',343,180,110,50,'Lab applications','actor'),
  ('p4',171,75,110,50,'4.0 Sanitize and\nverify evidence','process'),('d2',343,75,110,50,'D2 Evidence /\nverified findings','store'),('p5',171,0,110,40,'5.0 Export artifacts','process'),('e',343,0,110,40,'Reviewer / researcher','actor')],
  [('r','p2','versioned model'),('o','p1','run request'),('p1','d1','approved scope'),('p1','p2','initial state'),('p2','p3','candidate ID'),('d1','p3','constraints'),('p3','lab','bounded check'),('p3','p4','adapter status'),('lab','p4','observations'),('p4','d2','redacted evidence'),('p4','p2','updated state'),('d2','p5','verified records'),('p5','e','report / dataset')],h=420),
  H('4.4 Balancing and data stores'),
  'Operator scope enters 1.0; checks and observations cross the lab boundary through 3.0 and 4.0; artifacts leave through 5.0. The researcher supplies a model to 2.0. These preserve the context flows; the researcher entity is repeated for readability.',
  'D1 records immutable scope and run parameters. D2 stores redacted events, verifier verdicts, and evidence references. Training exports omit hidden scenario configuration and ground-truth labels from model feature columns.')
P('4. System design - DFD Level 2',
  F('4.4','DFD Level 2: decomposition of process 3.0',[
  ('in',0,265,125,45,'From 2.0\nCandidate action ID','actor'),('d1',320,265,130,45,'D1 Scope + budget','store'),('a',160,265,125,45,'3.1 Validate schema','process'),
  ('b',160,170,125,45,'3.2 Check scope,\npreconditions and budget','process'),('c',160,75,125,45,'3.3 Invoke registered\nlab adapter','process'),('lab',320,75,130,45,'Lab applications','actor'),
  ('rej',0,170,125,45,'Rejected-action record\nTo 4.0','actor'),('out',160,0,125,40,'3.4 Emit result\nTo 4.0','process')],
  [('in','a','candidate'),('a','b','typed action'),('d1','b','constraints'),('b','rej','denied + reason'),('b','c','permit'),('c','lab','bounded request'),('lab','out','result'),('c','out','adapter status')],h=325),
  H('4.5 Gate behavior'),
  'Authorization checks include target identity, action membership, input schema, remaining budget, run state, and adapter preconditions. Rejection is an auditable result, not a trigger to let the model invent an alternative target.',
  'A timeout or missing result becomes an indeterminate observation. It is never converted automatically into a confirmed weakness. Every allowed adapter call consumes the predefined cost, including failed attempts, to preserve fair budget comparisons.')

P('4. System design - use cases',
  F('4.5','Use-case view of the proposed system',[
  ('op',0,140,95,50,'Student operator','actor'),('su',0,260,95,45,'Supervisor','actor'),('re',358,140,95,50,'Researcher','actor'),('ex',358,20,95,45,'Examiner','actor'),
  ('u1',142,260,167,45,'UC01 Approve lab scope','process'),('u2',142,180,167,45,'UC02 Run assessment','process'),('u3',142,100,167,45,'UC03 Validate findings','process'),('u4',142,20,167,45,'UC04 Train / evaluate policy','process')],
  [('su','u1','approve'),('op','u2','start / stop'),('u1','u2','precondition'),('u2','u3','includes'),('re','u4','curate / train'),('u3','ex','review evidence'),('u4','ex','review metrics')],h=325),
  T('Table 4.1 - Use-case summaries',['Case','Precondition','Success / alternate outcome'],[['UC01','Provisioned lab and owner approval','Frozen scope; invalid manifest rejected'],['UC02','Approved scope, reset lab, model available','Budgeted run; stop or timeout triggers cleanup'],['UC03','Evidence IDs and verifier available','Confirmed / rejected / indeterminate finding'],['UC04','Versioned redacted dataset and split manifest','Model + metrics; incompatible schema rejected']],[48,175,230]),
  'UC02 includes scope validation on each action and evidence processing after each result. UC04 belongs to the research workflow and does not change the authority of UC01.')
P('4. System design - misuse cases',
  F('4.6','Misuse cases and mitigating controls',[
  ('bad',0,150,100,60,'Untrusted input /\nmisconfigured operator','actor'),('m1',137,265,150,43,'MC01 Expand target scope','process'),('m2',137,180,150,43,'MC02 Leak secret values','process'),('m3',137,95,150,43,'MC03 Forge finding evidence','process'),('m4',137,10,150,43,'MC04 Run without limits','process'),
  ('c1',330,265,123,43,'Deterministic gate'),('c2',330,180,123,43,'Redaction + canaries'),('c3',330,95,123,43,'Independent verifier'),('c4',330,10,123,43,'Budget + cancellation')],
  [('bad','m1','attempt'),('bad','m2','attempt'),('bad','m3','attempt'),('bad','m4','attempt'),('m1','c1','mitigated by'),('m2','c2','mitigated by'),('m3','c3','mitigated by'),('m4','c4','mitigated by')],h=325),
  H('4.6 Abuse prevention as system behavior'),
  'Misuse cases are requirements tests. A model-recommended external target must be rejected. Secret canaries must disappear before export. A policy-generated assertion must not create a finding without verifier evidence. Exhausted budgets and stop requests must prevent new adapter executions.',
  'The operator remains responsible for lab authorization. Network-level isolation supplements the application gate; neither a prompt nor a policy confidence score is a security boundary.')
P('4. System design - activity and state',
  F('4.7','Assessment activity flow',[
  ('a',150,280,150,35,'Load approved manifest'),('b',150,210,150,35,'Reset and verify lab'),('c',150,140,150,35,'Observe and rank actions'),('d',150,70,150,35,'Gate and execute action'),('e',150,0,150,35,'Verify, persist and update'),('stop',0,140,110,35,'Stop / cleanup'),('done',343,0,110,35,'Report + close')],
  [('a','b','valid'),('b','c','ready'),('c','d','action + budget'),('c','stop','stop / exhausted'),('d','e','result'),('e','c','continue'),('e','done','completed')],h=325),
  H('4.7 Run-state transition specification'),
  'CREATED becomes VALIDATED after scope checks, then READY after reset and health checks. READY becomes RUNNING only on explicit start. RUNNING transitions to STOPPING on completion, cancellation, exhausted budget, or fatal failure. STOPPING becomes CLOSED only after cleanup evidence; cleanup failure produces FAILED_REQUIRES_REVIEW.',
  'The activity loop above describes control flow. Figure 4.12 separately captures the persistent state machine, including failure and restart behavior.')

P('4. System design - sequence diagram',('sequence',),
  H('4.8 Normal and exceptional interaction'),
  'Each policy decision carries run ID, schema version, state digest, and ranked action IDs. The gate binds its permit to the current run and action; changing the state or target requires a new check. The runner returns an observation reference rather than a model-authored success claim.',
  'On denial, no adapter call occurs and the orchestrator records the rejection. On timeout, cancellation propagates to the runner and the verifier records an indeterminate result. The next state is constructed only from sanitized observations available to all compared policies.')
P('4. System design - domain class model',
  F('4.9','Proposed domain class model',[
  ('run',0,235,137,80,'AssessmentRun\nrunId, scopeHash, budget\nstart(), stop(), close()'),('policy',158,235,137,80,'PolicyService\nmodelId, schemaVersion\nrank(state, allowed)'),('gate',316,235,137,80,'ScopeGate\nmanifest, constraints\nauthorize(action)'),
  ('act',0,100,137,80,'ActionRecord\nactionId, cost, status\nvalidate(), cancel()'),('obs',158,100,137,80,'Observation\neventId, redactedFeatures\nvalidateSchema()'),('find',316,100,137,80,'VerifiedFinding\nfindingId, verdict\nevidenceRefs, dedupKey'),
  ('ver',158,0,137,55,'EvidenceVerifier\nverify(evidenceRefs)')],
  [('run','policy','uses'),('policy','gate','recommends to'),('run','act','1 : 0..*'),('act','obs','1 : 0..*'),('obs','find','supports'),('ver','find','creates verdict')],h=330),
  H('4.9 Class responsibilities'),
  'These are proposed conceptual classes, not existing Go type declarations. The policy has no execution method. Action adapters implement a registered interface with bounded inputs and cancellation. The verifier owns finding verdicts; the reporting layer reads immutable verified records.',
  'Persistence entities are detailed in the next diagram. Class associations describe responsibilities and object relationships rather than database foreign keys.')
P('4. System design - entity relationship diagram',
  F('4.10','Proposed relational evidence schema',[
  ('scope',0,245,136,72,'Scope\nPK scope_id\nmanifest_hash, approved_at'),('run',158,245,136,72,'Run\nPK run_id; FK scope_id\nFK model_id, seed, budget'),('model',316,245,137,72,'ModelVersion\nPK model_id\nschema_hash, artifact_hash'),
  ('action',0,105,136,82,'Action\nPK action_record_id\nFK run_id\ncatalog_id, cost, status'),('event',158,105,136,82,'Event\nPK event_id\nFK action_record_id\nredacted_payload_hash'),('finding',316,105,137,82,'Finding\nPK finding_id; FK run_id\nverdict, dedup_key'),('link',237,0,137,60,'FindingEvidence\nPK/FK finding_id\nPK/FK event_id')],
  [('scope','run','1 : many'),('model','run','1 : many'),('run','action','1 : many'),('action','event','1 : many'),('run','finding','1 : many'),('finding','link','1 : many'),('event','link','1 : many')],h=335),
  H('4.10 Integrity and retention'),
  'Foreign keys prevent orphan evidence. A unique key on run_id and dedup_key avoids counting repeated observations as new findings. FindingEvidence implements the many-to-many relationship between findings and events. ModelVersion records provenance rather than storing executable model content in the database.',
  'Store only redacted values in event payloads. Configure retention and deletion for each run. Use transactions for action completion, evidence insertion, and verifier verdicts.')
P('4. System design - deployment',
  F('4.11','Proposed isolated deployment topology',[
  ('host',0,260,453,55,'Research workstation: CPU, RAM, OS and versions recorded\nOperator interface + local training environment'),('ctrl',0,135,136,75,'Control container\nOrchestrator + gate\nEvidence database'),('ml',158,135,136,75,'Policy container\nRead-only model\nNo target-network route'),('lab',316,135,137,75,'Lab network\nSynthetic apps A/B/C\nRegistered runner'),('art',0,10,136,65,'Artifact directory\nDataset + models\nReports + checksums'),('iso',316,10,137,65,'Network policy\nDeny external egress\nAllow named lab services')],
  [('host','ctrl','run configuration'),('host','ml','model promotion'),('ctrl','ml','sanitized state'),('ctrl','lab','gated adapter call'),('ctrl','art','versioned outputs'),('iso','lab','enforced isolation')],h=330),
  H('4.11 Deployment constraints'),
  'The policy container cannot directly contact lab targets. The runner has only the network access required for the frozen scenario. Training artifacts are mounted read-only during evaluation. The model service accepts no arbitrary shell commands or executable serialized objects from untrusted sources.',
  'Containers improve repeatability but do not alone establish isolation. Verify routing, name resolution, host access, and egress denial before each assessment batch.')
P('4. System design - state and data lifecycle',
  F('4.12','Persistent run-state machine',[
  ('new',0,265,125,40,'CREATED'),('valid',164,265,125,40,'VALIDATED'),('ready',328,265,125,40,'READY'),('running',328,150,125,45,'RUNNING'),('stopping',164,150,125,45,'STOPPING'),('closed',0,150,125,45,'CLOSED'),('failed',164,30,125,60,'FAILED_REQUIRES\n_REVIEW')],
  [('new','valid','scope valid'),('valid','ready','lab healthy'),('ready','running','start'),('running','stopping','stop / end / fault'),('stopping','closed','cleanup verified'),('stopping','failed','cleanup failed'),('valid','failed','setup failure')],h=330),
  H('4.12 Crash and resume rules'),
  'A restarted controller never resumes a RUNNING record silently. It marks the interrupted run for review, verifies cleanup, and requires a new run or an explicitly documented resume protocol. CLOSED is immutable except for retention metadata.',
  H('4.13 Data lifecycle'),
  'Collect minimal telemetry, redact before durable storage, validate its schema, bind it to a run and action, derive verified labels, export a versioned dataset, then apply retention. Keep training splits and final test manifests immutable. Store model artifacts with checksums and training provenance.')

P('5. AI methodology - learning formulation',
  H('5.1 Decision problem'),
  'At step t, the policy receives observation state x_t, a permitted action mask A_t, and remaining budget b_t. It returns a ranking over A_t or STOP. Only the independently authorized top action is executed. The environment is partially observable; the feature state is not assumed to reveal all hidden application properties.',
  H('5.2 Initial supervised approach'),
  'Expert annotators label one or more useful next actions for sampled training states using documented assessment criteria. Record disagreements and acceptable alternatives rather than forcing a single arbitrary action. Train a classifier or action ranker on state-action examples, grouping all examples from the same scenario family into the same split.',
  'For a practical first implementation, compare multinomial logistic regression with gradient-boosted trees. Candidate features include completed-check indicators, observed outcome categories, evidence completeness, timeouts, and budget remaining. Action identity may be an input to a pairwise ranker; raw target names and hidden weakness flags may not.',
  H('5.3 Objective and decision rule'),
  'Fit the model using a documented classification or ranking loss with class weights chosen on training data. Tune hyperparameters and abstention thresholds on validation data only. Mask disallowed actions before selection; if no admissible action remains or confidence is insufficient, STOP or request operator review.',
  H('5.4 Scope of model training'),
  'The students train these policies themselves; using an API to generate a report is not the AI contribution. Reinforcement learning is a future extension requiring a reliable simulator and independently verified rewards. It is not required for the initial FYP.')
P('5. AI methodology - dataset and pipeline',
  F('5.1','Training and evaluation pipeline',[
  ('gen',0,265,130,50,'Versioned lab scenarios\nSynthetic identities'),('collect',160,265,130,50,'Sanitize observations\nExpert action labels'),('split',320,265,130,50,'Freeze group splits\nApp + scenario family'),('train',0,135,130,60,'Train on training set\nFit preprocessing here'),('val',160,135,130,60,'Validation only\nTune + calibrate'),('test',320,135,130,60,'Final holdout\nClosed-loop evaluation'),('reg',160,15,130,60,'Registry + report\nModel, data, code hashes')],
  [('gen','collect','episodes'),('collect','split','redacted examples'),('split','train','train groups'),('train','val','candidate model'),('val','test','frozen choice'),('test','reg','metrics + evidence')],h=330),
  H('5.5 Sampling and labels'),
  'Begin with a pilot to estimate class balance and annotation effort. A provisional collection target is 300-600 resettable assessment episodes across three lab applications and multiple configuration families; this is a planning estimate, not a guarantee of adequate statistical power. Freeze sample-size decisions using pilot variance before final evaluation.',
  'Training labels describe useful next actions. Evaluation labels describe independently verified weaknesses. The model never receives the latter as live input. Avoid duplicated templates or near-identical traces crossing split boundaries.')
P('5. AI methodology - features and uncertainty',
  T('Table 5.1 - Proposed observation schema',['Feature group','Examples','Restriction'],[['Assessment progress','Completed-check bitmap; remaining budget','No future outcomes or hidden scenario metadata'],['Observed behavior','Result category; redirect count; timeout flag','Only measurements available to every policy'],['Evidence quality','Missing-field count; verifier status from prior step','No unexecuted-check labels'],['Action context','Registered ID; fixed cost; observed preconditions','No unrestricted command text'],['Excluded data','Passwords, cookie values, auth headers, raw identifiers','Never exported as model inputs']],[105,175,173]),
  H('5.6 Calibration and abstention'),
  'Calibrate confidence on validation groups using a method appropriate to sample size. Report calibration error or Brier score along with the proportion of states on which the policy abstains. Compare coverage at matched abstention rules or count STOP decisions explicitly so selective reporting cannot inflate performance.',
  H('5.7 Distribution shift and feedback'),
  'Test missing fields, altered latency, application-family holdouts, and previously unseen combinations of known configuration factors. Detect schema incompatibility deterministically. Unexpected observations should produce a bounded stop or review request, not retraining during the final test.',
  H('5.8 Reproducibility'),
  'Record dataset hashes, split membership, annotation guideline version, code commit, dependency lockfile, random seeds, hyperparameters, model checksum, and actual hardware. Do not refit preprocessing on validation or test data.')

P('6. Implementation and integration plan',
  H('6.1 Baseline provenance'),
  'The source baseline inspected for report revision is Un-9oon/PhantomGate commit 8ae8437a4900b03fbaf187ac98bbde6127687efa [10]. The repository contains a Go proxy, storage, configuration, phishlet handling, a local fake target, and tests. File presence and source review do not establish that every feature works or that all tests pass.',
  T('Table 6.1 - Proposed module allocation',['Module','Responsibility','Implementation status'],[['research/orchestrator','Run state, budget and cancellation','Proposed'],['research/scope','Manifest validation and action permits','Proposed'],['research/adapters','Bounded synthetic-lab action interface','Proposed'],['research/evidence','Sanitization, verification, deduplication','Proposed'],['ml/data + ml/train','Dataset preparation and policy training','Proposed'],['ml/evaluate','Held-out closed-loop comparisons','Proposed'],['reports/','Evidence-linked academic and run reports','This revised design report only']],[132,217,104]),
  H('6.2 Integration contract'),
  'Retain existing code attribution and isolate new research modules. Expose typed lab observations through a narrow adapter rather than letting the model operate existing console commands freely. Add schema compatibility checks at each boundary. Audit storage and lifecycle behavior before using the framework as an experiment runner.',
  H('6.3 Delivery stages'),
  'Implement the resettable lab and verifier first, then fixed and heuristic baselines, then data collection and model training. A learned policy cannot be evaluated credibly on top of an unreliable ground-truth pipeline.')
P('6. Reliability and security engineering',
  T('Table 6.2 - Robustness work and verification',['Concern','Proposed change','Verification'],[['Durability','Transactional evidence store or atomic snapshot replacement','Interrupted-write and recovery fixtures'],['Concurrency','Immutable read snapshots; clear ownership','Concurrent serialization/mutation tests and race checks'],['Lifecycle','Explicit timeouts, cancellation and readiness','Listener failure, timeout and stop tests'],['Resources','Bounded queues, event sizes and run budgets','Sustained-load and backpressure tests'],['Privacy','Redaction before persistence and export','Seeded-secret canary scans'],['Model integrity','Pinned model/schema hashes; trusted loading','Tampered-artifact and schema-mismatch tests'],['Auditability','Append-only action/verdict records with provenance','Evidence-reference and deduplication validation']],[80,204,169]),
  H('6.4 Evidence-based readiness'),
  'The original report\'s assertions of universal MFA bypass, zero latency, zero technical debt, and certified production readiness are withdrawn in this revision. The previous report\'s claimed test passes have not been reproduced here. Test existence is acknowledged without treating it as a successful run.',
  'Robustness claims must state the supported OS, workload, hardware, failure cases, and measured results. NIST guidance [8] and WebAuthn [9] inform design assumptions; this report makes no certification or standards-compliance claim.')

P('7. Evaluation protocol',
  H('7.1 Experimental design'),
  'Use three synthetic applications with independently varied authentication-policy configurations. Hold out an entire application for testing and rotate the held-out application. Within the remaining applications, keep scenario families and near-duplicate configurations together when forming training and validation groups. Keep a separate final holdout for any final model selection claim.',
  H('7.2 Baselines and fairness'),
  'Compare a fixed checklist, uniform random selection among admissible untried actions, an expert-defined heuristic, logistic regression, and gradient-boosted trees. All policies receive the same observations, reset states, action costs, allowed actions, and termination rules. A heuristic must be designed before final-test inspection. Report its design effort alongside model-labeling effort.',
  H('7.3 Primary endpoint'),
  'For each run, count distinct confirmed weakness classes or instances under a predefined deduplication rule. Plot mean validated coverage C(B) against action budget B. Repeated evidence for the same underlying weakness counts once. Compare policies on the same scenario/seed pairs.',
  H('7.4 Statistical analysis'),
  'Use paired differences and bootstrap confidence intervals resampling independent scenario families, not individual correlated requests. Report per-application results as well as aggregates. Choose the number of independent repetitions after the pilot; a provisional minimum of five policy seeds is a planning floor, not a substitute for power analysis.',
  H('7.5 Ablations'),
  'Remove progress features, remove outcome features, disable calibration, and replace independent validation with naive success flags for an offline sensitivity study. Do not weaken authorization to conduct an ablation. Record the effect on coverage and false findings.')
P('7. Evaluation - metrics and planned results',
  T('Table 7.1 - Metrics and interpretation',['Metric','Definition','Interpretation'],[['Coverage at budget B','Distinct verified findings before budget exhaustion','Primary comparison; fixed deduplication rule'],['Finding precision','Confirmed / all reported findings','Indeterminate reports remain visible'],['Time to first confirmed finding','Elapsed time including policy overhead','Report no-finding runs as censored'],['Decision latency','p50 / p95 per policy decision','State hardware, batch size and warmup'],['Abstention rate','STOP/review decisions due to uncertainty / decisions','Report with coverage, not in isolation'],['Scope / privacy failures','Executed denied actions / leaked canaries','Must be zero in defined acceptance tests']],[112,180,161]),
  H('7.6 Results status'),
  'No model has been trained or evaluated as part of this document revision. No accuracy, coverage improvement, latency, or robustness result is available. The final report should replace this section with measured tables, coverage curves, confidence intervals, failure analyses, and links to immutable experiment manifests.',
  T('Table 7.2 - Results template (unmeasured)',['Policy','Coverage @ fixed B','Precision','p95 decision time'],[['Fixed checklist','Not measured','Not measured','Not measured'],['Random / heuristic','Not measured','Not measured','Not measured'],['Logistic regression','Not measured','Not measured','Not measured'],['Gradient-boosted trees','Not measured','Not measured','Not measured']],[125,113,100,115]),
  'Do not substitute illustrative numbers for actual results. Preserve unsuccessful runs and explain exclusions using criteria fixed before analysis.')

P('8. Project management and feasibility',('gantt',),
  T('Table 8.1 - Milestones and exit criteria',['Weeks','Deliverable','Exit criterion'],[['1-2','Scope, literature and protocol','Supervisor-reviewed question and frozen pilot plan'],['3-4','Lab, reset and verifier','Known fixtures pass; scope and redaction checks pass'],['5-6','Dataset pilot and baseline policies','Label agreement, split audit and sample plan recorded'],['7-8','Trained and calibrated policies','Reproducible training; validation-only selection'],['9-10','Held-out evaluation and reliability','Paired results, confidence intervals and fault tests'],['11-12','Report, demo and reproducibility pack','Independent rerun and source/PDF consistency']],[45,190,218]),
  H('8.1 Resources and costs'),
  'Plan for one local workstation, isolated application services, Python ML tooling, the Go framework, and storage for redacted traces. Use existing hardware where feasible. No monetary budget is asserted because local procurement prices and available resources were not supplied. Record actual costs, licenses, compute time, and contributor effort in the final submission.')
P('8. Risk register and academic integrity',
  T('Table 8.2 - Project risks',['Risk','Likelihood / impact','Mitigation'],[['Dataset leakage','Medium / high','Group splits; duplicate audit; freeze final holdout'],['Insufficient labels','High / medium','Pilot annotation effort; prioritize small models'],['Simulator artifacts','High / high','Hold out apps; vary benign conditions; disclose transfer limits'],['No ML improvement','Medium / medium','Strong baselines; publish null results honestly'],['Unsafe target selection','Low / high','Independent gate plus network isolation'],['Unreliable verifier','Medium / high','Known fixtures; manual evidence review subset'],['Deadline pressure','Medium / high','Supervised policy first; RL deferred'],['Template mismatch','Medium / low','Apply university template before submission']],[113,102,238]),
  H('8.2 Attribution and ethical conduct'),
  'Credit the existing repository and all reused code. Identify student-authored modules, dataset generation, annotation, model training, and evaluation separately. Do not claim ownership of prior interception techniques or paper contributions. Report the use of writing or coding assistance according to university policy.',
  H('8.3 Limitations'),
  'Synthetic applications cannot establish real-world attack success or safety. Three applications provide limited external validity. Expert labels encode annotator preferences. A finite catalogue constrains what can be discovered. An offline-trained policy can encounter unseen states during execution. These limitations should remain explicit even if laboratory results are positive.')
P('9. Conclusion and expected deliverables',
  'PhantomGate-Lab reframes the existing framework as a component of an AI-assisted offensive assessment workflow in an isolated laboratory. Its research objective is to evaluate learned test prioritization, not to claim a new interception technique. The AI recommends bounded actions; separate mechanisms enforce authorization and validate findings.',
  H('9.1 Expected deliverables'),
  B('A versioned, resettable synthetic authentication laboratory and rules-of-engagement manifest.', 'A registered action catalogue, deterministic scope gate, and evidence verifier.', 'A redacted dataset with annotation guidelines, group splits, and provenance.', 'Student-trained baseline and ranking models with documented hyperparameters.', 'A fair closed-loop evaluation with independently validated findings and uncertainty analysis.', 'Reliability evidence, an academic report, a demonstration script, and a reproducibility package.'),
  H('9.2 Conditions for the final claims'),
  'Claim a research contribution only after the related-work comparison and experiments establish what is added. Claim improved coverage only against the stated baselines, budgets, and held-out conditions. Claim robustness only within the workloads and failure cases actually tested. If the model does not improve over the heuristic, retain that result and analyze why.',
  H('9.3 Immediate next step'),
  'Confirm the university template and team details, agree on the finite lab action catalogue with the supervisor, implement the verifier and reset process, and complete a small pilot before committing to a larger training dataset.')

refs=[
('[1]','J. Schwartz and H. Kurniawati. Autonomous Penetration Testing using Reinforcement Learning. arXiv:1905.05965, 2019. Preprint.','https://arxiv.org/abs/1905.05965'),
('[2]','N. Becker, D. Reti, E. V. Ntagiou, M. Wallum, and H. D. Schotten. Evaluation of Reinforcement Learning for Autonomous Penetration Testing using A3C, Q-learning and DQN. arXiv:2407.15656, 2024. Preprint.','https://arxiv.org/abs/2407.15656'),
('[3]','G. Deng et al. PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing. 33rd USENIX Security Symposium, pp. 847-864, 2024.','https://www.usenix.org/conference/usenixsecurity24/presentation/deng'),
('[4]','Microsoft Research. CyberBattleSim. Research software project; source release discussed in 2021.','https://www.microsoft.com/en-us/research/project/cyberbattlesim/'),
('[5]','R. Simon, J. Carrasquel, E. M. Antoun, W. Mees, and P. Libin. NASimJax: A GPU-Accelerated Policy Learning Framework for Penetration Testing. arXiv:2603.19864v3, revised 4 October 2026. Preprint.','https://arxiv.org/abs/2603.19864v3'),
('[6]','B. Kondracki, B. Amin Azad, O. Starov, and N. Nikiforakis. Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits. ACM CCS, 2021. DOI: 10.1145/3460120.3484765.','https://briankondracki.com/assets/pdf/catching_transparent_phish.pdf'),
('[7]','E. Ulqinaku, H. Assal, A. Abdou, S. Chiasson, and S. Capkun. Is Real-time Phishing Eliminated with FIDO? Social Engineering Downgrade Attacks against FIDO Protocols. 30th USENIX Security Symposium, pp. 3811-3828, 2021.','https://www.usenix.org/conference/usenixsecurity21/presentation/ulqinaku'),
('[8]','K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh. Technical Guide to Information Security Testing and Assessment. NIST SP 800-115, September 2008. Guidance document.','https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf'),
('[9]','W3C. Web Authentication: An API for accessing Public Key Credentials - Level 2. W3C Recommendation, 8 April 2021. Specification.','https://www.w3.org/TR/webauthn-2/'),
('[10]','Un-9oon/PhantomGate. Source repository and original project report. Baseline commit 8ae8437a4900b03fbaf187ac98bbde6127687efa. Software artifact.','https://github.com/Un-9oon/PhantomGate/tree/8ae8437a4900b03fbaf187ac98bbde6127687efa')]
P('References',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[:5]],'Sources checked on 21 October 2026. This focused review does not establish exhaustive coverage of the research literature.')
P('References - continued',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[5:]])
P('Appendix A. Validation and traceability matrix',
  T('Table A.1 - Planned acceptance tests',['Test','Requirement','Expected result / evidence'],[['AT01 Manifest rejection','FR01, NFR01','Invalid or external target denied before execution'],['AT02 Budget exhaustion','FR03','No new action after the budget reaches zero'],['AT03 Secret canary','FR04, NFR02','No seeded secret in DB export, model inputs or report'],['AT04 Verifier fixtures','FR06, NFR07','Known true/false/unknown cases classified correctly'],['AT05 Evidence deduplication','FR06','Repeated observations do not inflate findings'],['AT06 Schema mismatch','FR05','Incompatible model/state rejected explicitly'],['AT07 Crash recovery','NFR03','Committed evidence intact; interrupted run reviewed'],['AT08 Concurrent access','NFR04','No mutable snapshot leakage or detected races'],['AT09 Cancellation','FR07, NFR06','Runner stops; cleanup status persisted'],['AT10 Held-out replay','O3','Split hash stable; identical paired scenario seeds'],['AT11 Policy unavailable','FR03, FR05','Stop or explicitly configured fixed baseline; no hidden fallback'],['AT12 Report integrity','FR08','Each finding resolves to verified evidence']],[140,85,228]),
  'Execution status for every acceptance test above: not run in this report revision. Archive actual commands, logs, environment details, timestamps, and pass/fail outcomes when implementation is available.')
P('Appendix B. Detailed use and misuse specifications',
  H('UC02 - Run a bounded assessment'),
  'Actor: student operator. Preconditions: approved immutable scope, reset lab, compatible model, and configured budget. Trigger: explicit start request. Main flow: validate manifest; establish readiness; construct sanitized state; rank actions; enforce scope and budget; execute one registered action; verify and persist evidence; repeat or stop; clean up; export report. Postcondition: closed run with traceable actions and verified findings.',
  'Alternate flows: invalid scope -> reject before start; model unavailable -> stop or use a predeclared baseline with its identity recorded; adapter timeout -> indeterminate evidence; stop request -> cancel and clean up; cleanup failure -> review-required state. No alternate flow expands target scope.',
  H('MC01 - Attempt to expand authorization'),
  'Threat: a malformed model response or operator input names an external target or unregistered action. Expected control: gate rejects it and records the reason. Acceptance evidence: denial record and absence of a corresponding network request. Residual risk: faulty network policy; verify egress independently.',
  H('MC03 - Attempt to count unsupported findings'),
  'Threat: a model or adapter reports success without supporting server evidence. Expected control: the independent verifier marks the case rejected or indeterminate; only confirmed deduplicated findings enter the primary coverage metric. Acceptance evidence: fixtures with fabricated status messages and missing references.',
  H('Submission checklist'),
  'Complete team and institution fields; obtain real signatures; apply the institutional template; confirm reference style; attach actual results; include attribution and assistance disclosure; verify source/PDF consistency; demonstrate clean reset and reproducibility.')
P('Appendix C. Bounded assessment catalogue',
  'The following conceptual action categories make the proposed policy concrete. They are not commands or exploit procedures. Each requires a supervisor-approved lab adapter with explicit inputs, preconditions, cost, timeout, and independently verifiable evidence. The complete catalogue must be frozen before comparative evaluation.',
  T('Table C.1 - Proposed registered action categories',['ID','Lab assessment category','Expected observation'],[['A01','Inspect authentication-response metadata','Normalized flags and response category'],['A02','Compare access decisions for synthetic test roles','Expected versus observed authorization verdict'],['A03','Check synthetic-session expiry behavior','Server-confirmed expired/active state'],['A04','Check logout invalidation in a resettable fixture','Verifier-confirmed session lifecycle result'],['A05','Assess configured recovery-policy consistency','Observed policy category and evidence reference'],['A06','Repeat a prior lab check after remediation','Independent before/after comparison'],['STOP','End assessment and clean up','Closed run or cleanup-review state']],[40,233,180]),
  H('Action contract'),
  'Inputs: run ID, registered category ID, lab target ID, typed parameters, and current state digest. Outputs: status, observation reference, elapsed time, charged cost, and cancellation status. A category ID never grants permission to discover arbitrary targets or invoke unrestricted tools.',
  H('Ground truth and success criteria'),
  'The scenario manifest defines expected application behavior. The verifier compares observed evidence with that expectation and issues a confirmed, rejected, or indeterminate verdict. Scenario configuration is available to the verifier and evaluation harness only; the policy learns from prior observed results, not hidden labels.')

class Sequence(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=360
        xs=[40,135,230,325,420];names=['Operator','Orchestrator','Policy / gate','Lab runner','Verifier']
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="360"><rect width="100%" height="100%" fill="white"/>']
        for x,name in zip(xs,names):s.extend([f'<rect x="{x-38}" y="15" width="76" height="30" rx="3" fill="{PALE}" stroke="{BLUE}"/>',f'<text x="{x}" y="33" text-anchor="middle" font-family="Arial" font-size="8">{name}</text>',f'<line x1="{x}" y1="50" x2="{x}" y2="350" stroke="{BLUE}" stroke-dasharray="3 3"/>'])
        msgs=[(0,1,'Start approved run'),(1,2,'Rank permitted actions'),(2,1,'Action ID + confidence'),(1,2,'Authorize current action'),(2,1,'Permit or denial'),(1,3,'Execute if permitted'),(3,4,'Server evidence reference'),(4,1,'Confirmed / rejected / unknown'),(1,0,'Report after cleanup')]
        for i,(a,b,t) in enumerate(msgs):
            y=73+i*30;sgn=1 if xs[b]>xs[a] else -1
            s.extend([f'<path d="M {xs[a]} {y} H {xs[b]} M {xs[b]-sgn*5} {y-3} L {xs[b]} {y} L {xs[b]-sgn*5} {y+3}" fill="none" stroke="{BLUE}"/>',f'<text x="{(xs[a]+xs[b])/2}" y="{y-6}" text-anchor="middle" font-family="Arial" font-size="7.5">{html.escape(t)}</text>'])
        s.append('</svg>');(DIAG/'figure-4-8.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;xs=[40,135,230,325,420];names=['Operator','Orchestrator','Policy / gate','Lab runner','Verifier']
        for x,name in zip(xs,names):
            c.setFillColor(colors.HexColor(PALE));c.setStrokeColor(colors.HexColor(BLUE));c.roundRect(x-38,315,76,30,3,fill=1);c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica-Bold',8);c.drawCentredString(x,327,name);c.setDash(3,3);c.line(x,310,x,10);c.setDash()
        msgs=[(0,1,'Start approved run'),(1,2,'Rank permitted actions'),(2,1,'Action ID + confidence'),(1,2,'Authorize current action'),(2,1,'Permit or denial'),(1,3,'Execute if permitted'),(3,4,'Server evidence reference'),(4,1,'Confirmed / rejected / unknown'),(1,0,'Report after cleanup')]
        for i,(a,b,t) in enumerate(msgs):
            y=287-i*30;c.setStrokeColor(colors.HexColor(BLUE));c.line(xs[a],y,xs[b],y);sgn=1 if xs[b]>xs[a] else -1;c.line(xs[b],y,xs[b]-sgn*5,y+3);c.line(xs[b],y,xs[b]-sgn*5,y-3);c.setFont('Helvetica',7.5);c.setFillColor(colors.HexColor(NAVY));c.drawCentredString((xs[a]+xs[b])/2,y+6,t)

class Gantt(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=185
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="185"><rect width="100%" height="100%" fill="white"/>']
        for w in range(12):s.append(f'<text x="{125+w*26+13}" y="15" text-anchor="middle" font-family="Arial" font-size="8">{w+1}</text>')
        for i,label in enumerate(['Scope + literature','Lab + verifier','Dataset + baselines','Train + validate','Evaluate + harden','Report + demo']):
            y=26+i*25;s.append(f'<text x="0" y="{y+13}" font-family="Arial" font-size="8">{label}</text>')
            for w in range(12):s.append(f'<rect x="{125+w*26}" y="{y}" width="26" height="19" fill="white" stroke="#D7E0E5"/>')
            s.append(f'<rect x="{125+i*52}" y="{y+1}" width="52" height="17" fill="{BLUE}"/>')
        s.append('</svg>');(DIAG/'figure-8-1.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;labels=['Scope + literature','Lab + verifier','Dataset + baselines','Train + validate','Evaluate + harden','Report + demo'];left=125;cw=26
        c.setFont('Helvetica',8)
        for w in range(12):c.drawCentredString(left+w*cw+cw/2,170,str(w+1))
        for i,label in enumerate(labels):
            y=140-i*25;c.setFillColor(colors.HexColor(NAVY));c.drawString(0,y+6,label)
            for w in range(12):c.setStrokeColor(colors.HexColor('#D7E0E5'));c.rect(left+w*cw,y,cw,19,stroke=1,fill=0)
            c.setFillColor(colors.HexColor(BLUE));c.rect(left+i*2*cw,y+1,2*cw,17,stroke=0,fill=1)

def roman(n):
    vals=[(10,'x'),(9,'ix'),(5,'v'),(4,'iv'),(1,'i')];s=''
    for v,t in vals:
        while n>=v:s+=t;n-=v
    return s
def page_label(i):return '' if i==1 else roman(i-1) if i<=5 else str(i-5)
for pi,(title,blocks) in enumerate(pages,1):
    for b in blocks:
        if isinstance(b,tuple) and b[0]=='f':figs.append((b[1],b[2],pi))
        elif isinstance(b,tuple) and b[0]=='t':tabs.append((b[1],pi))
        elif isinstance(b,tuple) and b[0]=='sequence':figs.append(('4.8','Assessment interaction sequence',pi))
        elif isinstance(b,tuple) and b[0]=='gantt':figs.append(('8.1','Proposed twelve-week schedule',pi))

story=[]
def add_md_table(headers,rows):
    md.append('| '+' | '.join(headers)+' |\n| '+' | '.join(['---']*len(headers))+' |')
    for row in rows:md.append('| '+' | '.join(str(x).replace('|','/') for x in row)+' |')
for pi,(title,blocks) in enumerate(pages,1):
    if pi>1:story.append(PageBreak())
    md.append('\n# '+title+'\n')
    if pi!=1:story.append(para(title,'H1F'))
    for block in blocks:
        if isinstance(block,str):story.append(para(block));md.append(re.sub('<[^>]+>','',html.unescape(block))+'\n');continue
        kind=block[0]
        if kind=='h':story.append(para(block[1],'H2F'));md.append('## '+block[1]+'\n')
        elif kind=='b':
            for x in block[1]:story.append(para('&#8226; '+x));md.append('- '+x)
        elif kind=='t':
            _,cap,heads,rows,widths=block;story.extend([para(cap,'CaptionF'),table(heads,rows,widths),Spacer(1,12)]);md.append('**'+cap+'**');add_md_table(heads,rows)
        elif kind=='f':
            _,num,cap,nodes,edges,height,notes=block;key='figure-'+num.replace('.','-');story.extend([Diagram(key,cap,nodes,edges,height,notes),para('Figure '+num+' - '+cap+'. Proposed design.','CaptionF')]);md.append(f'![Figure {num} - {cap}](diagrams/{key}.svg)\n')
        elif kind=='cover':
            story.extend([Spacer(1,40),para('FINAL YEAR PROJECT | REVISED DESIGN REPORT','SmallF'),Spacer(1,35),para('PhantomGate-Lab','CoverF'),para('AI-Assisted Penetration Testing for Controlled Authentication Assessment','SubF'),Spacer(1,25),para('Penetration Testing + Artificial Intelligence','H2F'),Spacer(1,20),para('Proposed contribution: a student-trained action-selection policy evaluated against fixed, random, and heuristic assessment sequences.'),Spacer(1,65),table(['Submission information','Status'],[['Student(s) / registration ID(s)','Not supplied'],['University / department / degree','Not supplied'],['Supervisor / academic session','Not supplied'],['Revision / prepared','2.0 - Design proposal / 21 October 2026']],[210,243]),Spacer(1,28),para('Existing framework acknowledged. New AI and reliability modules are proposed. No experimental results are claimed.','SmallF')]);md.extend(['**AI-Assisted Penetration Testing for Controlled Authentication Assessment**','Revision 2.0 - Design proposal. Prepared 21 October 2026.','Team, university, department, degree, supervisor and academic session: not supplied.'])
        elif kind=='toc':
            rows=[]
            for j,(tt,_) in enumerate(pages,1):
                if j in [2,3,5] or (j>=6 and (j==6 or tt.split(' - ')[0]!=pages[j-2][0].split(' - ')[0])):
                    # Collapse chapter continuations to chapter starts.
                    if j>=6 and not (re.match(r'^\d+\. ',tt) and (j==6 or tt.split('.')[0]!=pages[j-2][0].split('.')[0])) and not tt.startswith(('References','Appendix')):continue
                    if tt=='References - continued':continue
                    rows.append([tt,page_label(j)])
            story.append(table(['Section','Page'],rows,[403,50]));story.extend([Spacer(1,18),para('Page numbering: preliminary pages use Roman numerals; main text and appendices use Arabic numerals. Figures are conceptual proposed designs unless explicitly stated otherwise.','SmallF')])
            add_md_table(['Section','Page'],rows)
        elif kind=='lists':
            text='<b>Figures</b><br/>'+'<br/>'.join(f'{n} {html.escape(t)} <b>{page_label(p)}</b>' for n,t,p in figs)
            story.append(para(text,'SmallF'));story.append(Spacer(1,7))
            story.append(para('<b>Tables</b><br/>'+'<br/>'.join(f'{html.escape(t)} <b>{page_label(p)}</b>' for t,p in tabs),'SmallF'))
            story.append(para('<b>Abbreviations</b><br/>AI: Artificial Intelligence; AiTM: Adversary-in-the-Middle; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; RL: Reinforcement Learning; SSO: Single Sign-On; MFA: Multi-Factor Authentication; PK/FK: Primary/Foreign Key.','SmallF'))
            add_md_table(['Figure','Title','Page'],[[n,t,page_label(p)] for n,t,p in figs])
            add_md_table(['Table','Page'],[[t,page_label(p)] for t,p in tabs])
            md.append('AI: Artificial Intelligence; AiTM: Adversary-in-the-Middle; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; RL: Reinforcement Learning; SSO: Single Sign-On; MFA: Multi-Factor Authentication; PK/FK: Primary/Foreign Key.')
        elif kind=='sequence':story.extend([Sequence(),para('Figure 4.8 - Assessment interaction sequence. Proposed design.','CaptionF')]);md.append('![Figure 4.8 - Assessment interaction sequence](diagrams/figure-4-8.svg)')
        elif kind=='gantt':story.extend([Gantt(),para('Figure 8.1 - Proposed twelve-week schedule; relative weeks, not calendar commitments.','CaptionF')]);md.append('![Figure 8.1 - Proposed twelve-week schedule](diagrams/figure-8-1.svg)')

def footer(c,doc):
    i=doc.page;c.saveState()
    c.bookmarkPage('page-'+str(i));c.addOutlineEntry(pages[i-1][0],'page-'+str(i),level=0,closed=False)
    if i>1:
        c.setStrokeColor(colors.HexColor('#D7E0E5'));c.line(78,48,531,48);c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY));c.drawString(78,35,'PHANTOMGATE-LAB | DESIGN PROPOSAL');c.drawRightString(531,35,page_label(i));c.setFont('Helvetica',7.5);c.drawString(78,805,'FINAL YEAR PROJECT - PENETRATION TESTING AND ARTIFICIAL INTELLIGENCE')
    else:
        c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(3);c.line(63,85,63,750)
    c.restoreState()

doc=SimpleDocTemplate(str(OUT/'PhantomGate-Project-Report.pdf'),pagesize=A4,leftMargin=78,rightMargin=64,topMargin=60,bottomMargin=66,title='PhantomGate-Lab: AI-Assisted Penetration Testing',author='PhantomGate project team - details pending',subject='Revised FYP design proposal; no measured results')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
(OUT/'PhantomGate-Project-Report.md').write_text('\n'.join(md),encoding='utf-8')
reader=PdfReader(OUT/'PhantomGate-Project-Report.pdf')
print(json.dumps({'expected_pages':len(pages),'actual_pages':len(reader.pages),'figures':len(figs),'tables':len(tabs),'bytes':(OUT/'PhantomGate-Project-Report.pdf').stat().st_size}))
for i,p in enumerate(reader.pages,1):print(i, (p.extract_text() or '').splitlines()[1:3])
