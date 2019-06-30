package com.company;

import org.xipki.security.pkcs11.iaik.IaikP11Module;
import javafx.beans.binding.ObjectExpression;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.pe.CertificateTableEntry;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;

import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.operator.*;
import org.bouncycastle.util.Store;
import net.jsign.pe.PEFile;
import sun.security.pkcs.PKCS7;
import sun.security.x509.AlgorithmId;
import sun.security.x509.KeyUsageExtension;

import java.io.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Main {

    public static void main(String[] args) throws IOException, CMSException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, OperatorCreationException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        File file = new File("EXES/TeamViewer_Setup.exe");
        PEFile peFile = new PEFile(file);


        /*CMSSignedData xch = peFile.getSignatures().get(0);

        Store<X509CertificateHolder> store = xch.getCertificates();

        Iterator it = store.getMatches(null).iterator();

        while(it.hasNext()) {

            X509CertificateHolder cert = (X509CertificateHolder) it.next();
            *//*System.out.println(cert.getIssuer());

            System.out.println(cert.getSubject() + "\n");*//*

            System.out.println("Signer: " + cert.getIssuer());
            System.out.println("Subject: " + cert.getSubject());
            System.out.println("Serial No: " + cert.getSerialNumber());
            System.out.println();
        }*/


        ArrayList<DigestAlgorithm> digestAlgorithms = new ArrayList<>();
        List<CMSSignedData> signatures = peFile.getSignatures();


        ArrayList<DigestInfo> digestInfos = new ArrayList<>();

        if (!signatures.isEmpty()) {

            System.out.println("Signatures found: " + signatures.size());
            for (CMSSignedData signedData : signatures) {

                ContentInfo contentInfo = signedData.toASN1Structure();

                SignedData signedData1 = SignedData.getInstance(contentInfo.getContent());

                ContentInfo contentInfo1 = signedData1.getEncapContentInfo();

                //Study ASN1Dump.dumpAsString() to implement getSpcIndirectDataContent(...) or any other ASN.1 parser
                DigestInfo digestInfo = getSpcIndirectDataContent(contentInfo1);
                digestInfos.add(digestInfo);

                /*
                System.out.println(content.getContentType());

                SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(content.write(System.out));
                System.out.println(spcIndirectDataContent.toASN1Primitive());*/

                /*SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
                X509CertificateHolder certificate = (X509CertificateHolder) signedData.getCertificates().getMatches(signerInformation.getSID()).iterator().next();
                DigestAlgorithm algorithm = DigestAlgorithm.of(signerInformation.getDigestAlgorithmID().getAlgorithm());
                System.out.println("Version         :" + certificate.getVersionNumber());
                System.out.println("Serial number   :" + certificate.getSerialNumber());
                System.out.println("Algorithm       :" + algorithm.id);
                System.out.println("Issuer          :" + certificate.getIssuer().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue());
                System.out.println("Valid from      :" + certificate.getNotBefore());
                System.out.println("Valid to        :" + certificate.getNotAfter());

                DERBitString subjectUniqueId = certificate.toASN1Structure().getTBSCertificate().getSubjectUniqueId();
                System.out.println("Subject         :" + certificate.getSubject().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue());
                System.out.println("Subject Id      :" + subjectUniqueId);
                System.out.println("Public key      :" + certificate.getSubjectPublicKeyInfo().getPublicKeyData());
                System.out.println(certificate.toASN1Structure());
                */

                Store store = signedData.getCertificates();
                SignerInformationStore signers = signedData.getSignerInfos();
                signedData.getSignedContent();
                Collection<SignerInformation> c = signers.getSigners();

                for(SignerInformation signer : c) {

                    X509CertificateHolder h = (X509CertificateHolder) store.getMatches(signer.getSID()).iterator().next();



                    digestAlgorithms.add(DigestAlgorithm.of(new ASN1ObjectIdentifier(signer.getDigestAlgOID())));

                    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                    X509Certificate certificate = converter.getCertificate(h);
                    PublicKey key = certificate.getPublicKey();
                    KeyUsageExtension extension = new KeyUsageExtension(certificate.getKeyUsage());
                    Signature signature = Signature.getInstance(certificate.getSigAlgName());
                    signature.initVerify(key);

                    signature.update(signer.getEncodedSignedAttributes());
                    printDigest(signer.getEncodedSignedAttributes());
                    printDigest(signer.getSignedAttributes().toASN1Structure().getEncoded());
                    System.out.println(signature.verify(signer.getSignature()));

//                    signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

                    //Attempt to implement doVerify() from SignerInformation.java

                    ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(CMSAttributes.messageDigest, "message-digest", signer);
                    System.out.println(validMessageDigest);

                    if (validMessageDigest == null) {

                        throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                    } else {

                        if (!(validMessageDigest instanceof ASN1OctetString)) {
                            throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                        }

                        ASN1OctetString signedMessageDigest = (ASN1OctetString)validMessageDigest;
                        /*if (!Arrays.constantTimeAreEqual(this.resultDigest, signedMessageDigest.getOctets())) {
                            throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
                        }*/

                        System.out.println(signedMessageDigest);
                    }

//                    signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(h));

                    System.out.println("Vendor: " + h.getSubject().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue());

                    SignerInformationStore counters = signer.getCounterSignatures();
                    Collection<SignerInformation> c1 = counters.getSigners();

                    X509CertificateHolder h1 = null;
                    for(SignerInformation counter : c1) {

                        h1 = (X509CertificateHolder) store.getMatches(counter.getSID()).iterator().next();

                        System.out.println("Counter Signer: " + h1.getSubject().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue());
                    }
                }
            }
        }

        for(DigestInfo digestInfo : digestInfos) {

            DigestAlgorithm d = DigestAlgorithm.of(digestInfo.getAlgorithmId().getAlgorithm());
            System.out.print("Computed Hash: ");
            for (byte b : peFile.computeDigest(d)) {
                String st = String.format("%02X", b);
                System.out.print(st);
            }
            System.out.println();

            System.out.print("Embedded Hash: ");
            for (byte b : digestInfo.getDigest()) {
                String st = String.format("%02X", b);
                System.out.print(st);
            }
            System.out.println();

            System.out.println("Does the hashes match: " + Arrays.equals(peFile.computeDigest(d), digestInfo.getDigest()));
        }
    }

    private static X509Certificate convertToCert(X509CertificateHolder certificateHolder) throws CertificateException, IOException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));

        return cert;
    }

    private static ASN1Primitive getSingleValuedSignedAttribute(ASN1ObjectIdentifier var1, String var2, SignerInformation signerInformation) throws CMSException {
        AttributeTable var3 = signerInformation.getSignedAttributes();


            AttributeTable var4 = signerInformation.getSignedAttributes();
            if (var4 == null) {
                return null;
            } else {
                ASN1EncodableVector var5 = var4.getAll(var1);
                switch(var5.size()) {
                    case 0:
                        return null;
                    case 1:
                        Attribute var6 = (Attribute)var5.get(0);
                        ASN1Set var7 = var6.getAttrValues();
                        if (var7.size() != 1) {
                            throw new CMSException("A " + var2 + " attribute MUST have a single attribute value");
                        }

                        return var7.getObjectAt(0).toASN1Primitive();
                    default:
                        throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the " + var2 + " attribute");
                }
            }

    }

    private static List<CertificateTableEntry> getCertificateTable(List<CMSSignedData> cmsSignedData) {

        List<CertificateTableEntry> entries = new ArrayList<>();
        Iterator it = cmsSignedData.iterator();

        if (it.hasNext()) {

            try {
                entries.add(new CertificateTableEntry((CMSSignedData)it.next()));

                // todo read the remaining entries (but Authenticode use only one, extra signatures are appended as a SPC_NESTED_SIGNATURE unauthenticated attribute)
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return entries;
    }

    private static byte[] pad(byte[] data, int multiple) {
        if (data.length % multiple == 0) {
            return data;
        } else {
            byte[] copy = new byte[data.length + (multiple - data.length % multiple)];
            System.arraycopy(data, 0, copy, 0, data.length);
            return copy;
        }
    }



    private static DigestInfo getSpcIndirectDataContent(ContentInfo contentInfo) {

        DigestInfo digestInfo;

        AlgorithmIdentifier algId = null;
        byte[] digest = null;

        if((contentInfo.getContentType().getId()).equals(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID.getId())) {

            ASN1Primitive obj = contentInfo.getContent().toASN1Primitive();

            if(obj instanceof ASN1Sequence) {

                Enumeration e = ((ASN1Sequence)obj).getObjects();

                e.nextElement();
                Object messageDigestObj = e.nextElement();

                if(messageDigestObj instanceof ASN1Sequence) {

                    Enumeration e1 = ((ASN1Sequence)messageDigestObj).getObjects();


                    Object seq = e1.nextElement();
                    Object digestObj = e1.nextElement();

                    if(seq instanceof ASN1Sequence) {

                        Enumeration e2 = ((ASN1Sequence)seq).getObjects();

                        Object digestAlgorithmObj = e2.nextElement();

                        if(digestAlgorithmObj instanceof ASN1ObjectIdentifier) {

                            System.out.println(((ASN1ObjectIdentifier) digestAlgorithmObj).getId());
                            AlgorithmIdentifier a = new DefaultDigestAlgorithmIdentifierFinder().find(new DefaultAlgorithmNameFinder().getAlgorithmName((ASN1ObjectIdentifier) digestAlgorithmObj));
                            algId = AlgorithmIdentifier.getInstance(a);
                        }
                    }

                    if(digestObj instanceof ASN1OctetString) {

                        ASN1OctetString oct = (ASN1OctetString)digestObj;

                        digest = oct.getOctets();
                    }
                }
            }
        }

        digestInfo = new DigestInfo(algId, digest);

        return digestInfo;
    }

    private static void printDigest(byte[] digest) {

        for (byte b : digest) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println();
    }
}