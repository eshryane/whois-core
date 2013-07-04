//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-2
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: xxx
//


package net.ripe.db.whois.api.whois.rdap.domain.vcard;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import net.ripe.db.whois.api.whois.rdap.VcardObject;


/**
 * <p>Java class for nEntryValueType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="nEntryValueType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="n1" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="n2" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="n3" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="n4" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="nPost" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "nEntryValueType", propOrder = {
    "n1",
    "n2",
    "n3",
    "n4",
    "nPost"
})
public class NEntryValueType
    extends VcardObject
    implements Serializable
{

    @XmlElement(required = true, defaultValue = "")
    protected String n1;
    @XmlElement(required = true, defaultValue = "")
    protected String n2;
    @XmlElement(required = true, defaultValue = "")
    protected String n3;
    @XmlElement(required = true, defaultValue = "")
    protected String n4;
    @XmlElement(required = true)
    protected List<String> nPost;

    /**
     * Sets the value of the n1 property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setN1(String value) {
        this.n1 = value;
    }

    /**
     * Sets the value of the n2 property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setN2(String value) {
        this.n2 = value;
    }

    /**
     * Sets the value of the n3 property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setN3(String value) {
        this.n3 = value;
    }

    /**
     * Sets the value of the n4 property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setN4(String value) {
        this.n4 = value;
    }

    /**
     * Gets the value of the nPost property.
     *
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the nPost property.
     *
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getNPost().add(newItem);
     * </pre>
     *
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     *
     *
     */
    public List<String> getNPost() {
        if (nPost == null) {
            nPost = new ArrayList<String>();
        }
        return this.nPost;
    }

    /**
     * Gets the value of the n1 property.
     *
     */
    public String getN1() {
        if (null == n1) {
            return "";
        }
        return n1;
    }

    /**
     * Gets the value of the n2 property.
     *
     */
    public String getN2() {
        if (null == n2) {
            return "";
        }
        return n2;
    }

    /**
     * Gets the value of the n3 property.
     *
     */
    public String getN3() {
        if (null == n3) {
            return "";
        }
        return n3;
    }

    /**
     * Gets the value of the n4 property.
     *
     */
    public String getN4() {
        if (null == n4) {
            return "";
        }
        return n4;
    }

}