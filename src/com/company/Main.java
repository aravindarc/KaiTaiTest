package com.company;





import com.sun.crypto.provider.*;
import com.sun.security.sasl.Provider;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.pe.CertificateTableEntry;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;

import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import net.jsign.pe.DataDirectory;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import sun.misc.IOUtils;
import sun.security.jca.ProviderList;
import sun.security.jgss.wrapper.SunNativeProvider;
import sun.security.provider.Sun;

import java.io.*;

import java.net.ConnectException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import static com.google.common.primitives.Chars.fromByteArray;

public class Main {

    public static void main(String[] args) throws IOException, CMSException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        File file = new File("EXES/ideaIC-2019.1.3.exe");
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

        //attempt to get protected SignerInfo in SignerInformation Class
        List<CertificateTableEntry> certTable = getCertificateTable(signatures);

        for(CertificateTableEntry entry : certTable) {


        }
        if (!signatures.isEmpty()) {

            System.out.println("Signatures found: " + signatures.size());
            for (CMSSignedData signedData : signatures) {

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
                Collection<SignerInformation> c = signers.getSigners();

                for(SignerInformation signer : c) {

                    X509CertificateHolder h = (X509CertificateHolder) store.getMatches(signer.getSID()).iterator().next();

                    digestAlgorithms.add(DigestAlgorithm.of(new ASN1ObjectIdentifier(signer.getDigestAlgOID())));

                    X509Certificate cert = convertToCert(h);

//                    signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

                    //Attempt to implement doVerify() from SignerInformation.java
                    ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(CMSAttributes.messageDigest, "message-digest", signer);
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

                        System.out.println(signedMessageDigest.toString());
                    }

                    System.out.println(new DefaultAlgorithmNameFinder().getAlgorithmName(ASN1ObjectIdentifier.getInstance(h.getSignatureAlgorithm().getAlgorithm())) + ", " + h.getSignatureAlgorithm().getAlgorithm().getId());
                    DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(new ASN1ObjectIdentifier(signer.getDigestAlgOID()));
                    peFile.computeDigest(digestAlgorithm);

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

        for(DigestAlgorithm d : digestAlgorithms) {
            System.out.println(d);
            System.out.println(peFile.computeDigest(d));
        }
    }

    private static X509Certificate convertToCert(X509CertificateHolder certificateHolder) throws CertificateException, IOException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));

        return cert;
    }

    private static ASN1Primitive getSingleValuedSignedAttribute(ASN1ObjectIdentifier var1, String var2, SignerInformation signerInformation) throws CMSException {
        AttributeTable var3 = signerInformation.getUnsignedAttributes();
        if (var3 != null && var3.getAll(var1).size() > 0) {
            throw new CMSException("The " + var2 + " attribute MUST NOT be an unsigned attribute");
        } else {
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
}