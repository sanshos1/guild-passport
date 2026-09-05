from conftest import CONTRACT
U=['https://registry.example/issuer','https://credential.example/record']
def mocks(v):
 v.strict_mocks=True;v.check_pickling=True;v.mock_web(r'registry\.example',{'status':200,'body':'Issuer authorized.'});v.mock_web(r'credential\.example',{'status':200,'body':'Credential matches subject and Builder qualification.'});v.mock_llm(r'.*Verify that registry.*','{"valid":true,"claim_codes":["BUILDER"]}');v.mock_llm(r'.*Independently verify.*','{"valid":true}')
def test_full(direct_vm,direct_deploy):
 c=direct_deploy(CONTRACT);subject=c.admin;c.authorize_issuer(subject,True);c.draft('P1',subject,'Builder',U);c.consent('P1');mocks(direct_vm);c.activate('P1');assert c.get_passport('P1')['state']=='ACTIVE';c.revoke('P1');assert c.get_passport('P1')['state']=='REVOKED'
def test_duplicate_sources(direct_vm,direct_deploy):
 c=direct_deploy(CONTRACT);c.authorize_issuer(c.admin,True);c.draft('A',c.admin,'Builder',U)
 with direct_vm.expect_revert('authorized unique'):c.draft(' a ',c.admin,'Builder',U)
 with direct_vm.expect_revert('independent'):c.draft('B',c.admin,'Builder',[U[0],U[0]])
def test_forged(direct_vm,direct_deploy):
 c=direct_deploy(CONTRACT);c.authorize_issuer(c.admin,True);c.draft('X',c.admin,'Builder',U);c.consent('X');mocks(direct_vm);x=c._verify(c.passports['X']);assert direct_vm.run_validator(leader_result=x);x=dict(x);x['digests']=x['digests'][::-1];assert not direct_vm.run_validator(leader_result=x)
