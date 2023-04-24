ifeq ($(ARCH),)
 ifeq ($(OS),Windows_NT)
   ARCH=MSVC-x64-Debug
 else
   ARCH = $(shell gcc -dumpmachine)
 endif
endif

ifeq (,$(CERTGEN))
 $(error CERTGEN variable shall point to the certgen project)
endif

outdir=certificates
in=profiles
xerdir=xer
depdir=temp
keydir=certificates
iutdir=iut

asn1certgen=$(CERTGEN)/build/$(ARCH)/certgen
asn1certidx=$(CERTGEN)/build/$(ARCH)/certidx -n

xsl_cvt=$(CERTGEN)/certgen/asn1certgen.xslt
xsl_dep=$(CERTGEN)/certgen/prof2dep.xsl

profiles=$(wildcard $(in)/*.xml)
certificates_oer=$(patsubst $(in)/%.xml, $(outdir)/%.oer, $(profiles))
certificates_xer=$(patsubst $(in)/%.xml, $(xerdir)/%.xer, $(profiles))
deps=$(patsubst $(in)/%.xml, $(depdir)/%.dep, $(profiles))

all: $(sort $(outdir) $(xerdir) $(depdir)) $(outdir)/index.lst

$(sort $(outdir) $(xerdir) $(depdir) $(iutdir)):
	mkdir -p $@
clean:
	rm -f $(certificates_oer) $(certificates_xer)

$(certificates_xer): $(xerdir)/%.xer : $(in)/%.xml
	xsltproc $(xsl_cvt) $< | xmllint --format -o $@ -

$(outdir)/index.lst: $(certificates_oer)
	$(asn1certidx) -o $@ $^

$(certificates_oer): $(outdir)/%.oer : $(xerdir)/%.xer
	$(asn1certgen) -o $(outdir) -K $(keydir) $<

$(deps): $(depdir)/%.dep : $(in)/%.xml
	-mkdir -p $(depdir)
	xsltproc --param profile "'$*'" -o $@ $(xsl_dep) $<

$(certificates_xer) : $(xsl_cvt)

certs_iut_at = $(filter $(outdir)/CERT_IUT_%_AT.oer, $(certificates_oer))
vkeys_iut_at = $(patsubst %.oer, %.vkey, $(certs_iut_at))
ekeys_iut_at = $(patsubst %.oer, %.ekey, $(certs_iut_at))

certs_iut := $(filter $(outdir)/CERT_IUT_%_RCA.oer, $(certificates_oer))
certs_iut += $(filter $(outdir)/CERT_IUT_%_AA.oer, $(certificates_oer))
certs_iut += $(certs_iut_at)

iut_files = $(patsubst $(outdir)/%, $(iutdir)/%, $(certs_iut) $(vkeys_iut_at) $(ekeys_iut_at))

install: $(iutdir) $(iut_files) $(iutdir)/index.lst

$(iut_files): $(iutdir)/%: $(outdir)/%
	-cp -f $< $@

$(iutdir)/index.lst: $(certs_iut)
	$(asn1certidx) -o $@ $^

$(vkeys_iut_at) $(ekeys_iut_at):

IUT_TC23 = CERT_IUT_C1_AT.oer CERT_IUT_C1_AT.vkey CERT_IUT_C1_AT.ekey CERT_IUT_CC_AA.oer CERT_IUT_C_RCA.oer CERT_TS_A_AT.oer CERT_IUT_A_AA.oer
IUT_TC24 = CERT_IUT_C2_AT.oer CERT_IUT_C2_AT.vkey CERT_IUT_C2_AT.ekey CERT_IUT_C2_AA.oer CERT_IUT_C_RCA.oer CERT_IUT_A_RCA.oer CERT_TS_A_AT.oer CERT_IUT_A_AA.oer
IUT_TC25 = CERT_IUT_A1_AT.oer CERT_IUT_A1_AT.vkey CERT_IUT_A1_AT.ekey CERT_IUT_A_AA.oer CERT_IUT_A_RCA.oer CERT_TS_A_AT.oer 
IUT_TC26 = CERT_IUT_A2_AT.oer CERT_IUT_A2_AT.vkey CERT_IUT_A2_AT.ekey CERT_IUT_A_AA.oer CERT_IUT_A_RCA.oer CERT_TS_A_AT.oer 
IUT_TC27 = CERT_IUT_A3_AT.oer CERT_IUT_A3_AT.vkey CERT_IUT_A3_AT.ekey CERT_IUT_A_AA.oer CERT_IUT_A_RCA.oer CERT_TS_A_AT.oer 
IUT_TC28 = CERT_IUT_A_AT_A8.oer CERT_IUT_A_AT_A8.vkey CERT_IUT_A_AT_A8.ekey CERT_IUT_A_AA_A8.oer CERT_IUT_A_RCA.oer CERT_TS_A_AT.oer CERT_IUT_A_AA.oer

IUT_TCS = TC23 TC24 TC25 TC26 TC27 TC28

define InstallTC
$(addprefix $(TC)/,$(IUT_$(TC))): $(TC)/% : $$(outdir)/%
	mkdir -p $(TC)
	-cp -f $$< $$@
endef
$(foreach TC, $(IUT_TCS), $(eval $(InstallTC)))

install_tc: $(foreach TC, $(IUT_TCS), $(addprefix $(TC)/, $(IUT_$(TC))))

include $(deps)
