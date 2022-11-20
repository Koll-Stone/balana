/*
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.balana.finder.impl;

import java.net.URI;
import java.util.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.balana.AbstractPolicy;
import org.wso2.balana.DOMHelper;
import org.wso2.balana.MatchResult;
import org.wso2.balana.Policy;
import org.wso2.balana.PolicyMetaData;
import org.wso2.balana.PolicyReference;
import org.wso2.balana.PolicySet;
import org.wso2.balana.VersionConstraints;
import org.wso2.balana.combine.PolicyCombiningAlgorithm;
import org.wso2.balana.combine.xacml3.DenyOverridesPolicyAlg;
import org.wso2.balana.ctx.EvaluationCtx;
import org.wso2.balana.ctx.Status;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.PolicyFinderModule;
import org.wso2.balana.finder.PolicyFinderResult;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.wso2.balana.ParsingException;

/**
 * @author qiwei
 * this is an updatable policy finder module
 * it can change stored policies by retreiving new policy from a List<Document>
 */
public class updatablePolicyFinderModule extends PolicyFinderModule {

    private PolicyFinder finder = null;

    private Map<URI, AbstractPolicy> policies;

    private PolicyCombiningAlgorithm combiningAlg;

    /**
     * the logger we'll use for all messages
     */
    private static final Log log = LogFactory.getLog(updatablePolicyFinderModule.class);


//    public static void main(String[] args) {
//        updatablePolicyFinderModule upfm = new updatablePolicyFinderModule();
//        PolicyFinder policyFinder = new PolicyFinder();
//        upfm.init(policyFinder);
//    }

    public updatablePolicyFinderModule() {
        policies = new HashMap<URI, AbstractPolicy>();
        combiningAlg = new DenyOverridesPolicyAlg();
    }


    public void init(PolicyFinder finder) {

        this.finder = finder;
    }


    public PolicyFinderResult findPolicy(EvaluationCtx context) {
        log.debug("findpolicy function in updatablePolicyFinderModule is called");
        ArrayList<AbstractPolicy> selectedPolicies = new ArrayList<AbstractPolicy>();
        Set<Map.Entry<URI, AbstractPolicy>> entrySet = policies.entrySet();

        // iterate through all the policies we currently have loaded
        for (Map.Entry<URI, AbstractPolicy> entry : entrySet) {

            AbstractPolicy policy = entry.getValue();
            MatchResult match = policy.match(context);
            int result = match.getResult();

            // if target matching was indeterminate, then return the error
            if (result == MatchResult.INDETERMINATE)
                return new PolicyFinderResult(match.getStatus());

            // see if the target matched
            if (result == MatchResult.MATCH) {

                if ((combiningAlg == null) && (selectedPolicies.size() > 0)) {
                    // we found a match before, so this is an error
                    ArrayList<String> code = new ArrayList<String>();
                    code.add(Status.STATUS_PROCESSING_ERROR);
                    Status status = new Status(code, "too many applicable "
                            + "top-level policies");
                    return new PolicyFinderResult(status);
                }

                // this is the first match we've found, so remember it
                selectedPolicies.add(policy);
            }
        }

        // no errors happened during the search, so now take the right
        // action based on how many policies we found
        switch (selectedPolicies.size()) {
            case 0:
                if (log.isDebugEnabled()) {
                    log.debug("No matching XACML policy found");
                }
                return new PolicyFinderResult();
            case 1:
                return new PolicyFinderResult((selectedPolicies.get(0)));
            default:
                return new PolicyFinderResult(new PolicySet(null, combiningAlg, null, selectedPolicies));
        }
    }


    public PolicyFinderResult findPolicy(URI idReference, int type, VersionConstraints constraints,
                                         PolicyMetaData parentMetaData) {

        AbstractPolicy policy = policies.get(idReference);
        if (policy != null) {
            if (type == PolicyReference.POLICY_REFERENCE) {
                if (policy instanceof Policy) {
                    return new PolicyFinderResult(policy);
                }
            } else {
                if (policy instanceof PolicySet) {
                    return new PolicyFinderResult(policy);
                }
            }
        }

        // if there was an error loading the policy, return the error
        ArrayList<String> code = new ArrayList<String>();
        code.add(Status.STATUS_PROCESSING_ERROR);
        Status status = new Status(code,
                "couldn't load referenced policy");
        return new PolicyFinderResult(status);
    }


    public boolean isIdReferenceSupported() {
        return true;
    }


    public boolean isRequestSupported() {
        return true;
    }



    /**
     * @author qiwei
     * Private helper that tries to load the given file-based policy, and
     * returns null if any error occurs.
     *
     * @param policyDocuments the policies in memory
     *
     */
    public void loadPolicyBatchFromMemory(List<Document> policyDocuments) {
        for (Document d : policyDocuments) {
            AbstractPolicy p = loadPolicyFromMemory(d);
            policies.put(p.getId(), p);
            log.debug("add policy, id: " + p.getId());
        }
    }

    /**
     * @author qiwei
     * Private helper that tries to load the given Document policy, and
     * returns null if any error occurs.
     *
     * @param policyDocument the policies in memory
     * @return org.w3c.dom.Element
     */
    public AbstractPolicy loadPolicyFromMemory(Document policyDocument) {
        // based this largely on the FileBasedPolicyFinderModule implementation...strong potential for refactoring / pull-up here...
        AbstractPolicy policy = null;
        Element root = policyDocument.getDocumentElement();
        String name = DOMHelper.getLocalName(root);
        try {
            if (name.equals("Policy")) {

                policy = Policy.getInstance(root);

            } else if (name.equals("PolicySet")) {
                policy = PolicySet.getInstance(root, finder);
            }
        } catch (ParsingException e) {
            // just only logs
            log.error("Fail to load policy from memory: " + policyDocument.getDocumentElement().getNodeName(), e);
        }
        return policy;
    }


    /**
     * @author qiwei
     * public function that deletes a policy with the given id
     *
     * @param policy id
     **/
    public void deletePolicy(URI pid) {
        policies.remove(pid);
    }

    public Set<URI> showPolicies() {
        return policies.keySet();
    }

}
