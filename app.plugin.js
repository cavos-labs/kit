const configPlugins = require(require.resolve('@expo/config-plugins', {
  paths: [process.cwd(), __dirname],
}));
const { withAndroidManifest, withEntitlementsPlist, withInfoPlist } = configPlugins;

module.exports = function withCavosKit(config, props = {}) {
  const rpId = props.rpId;
  const scheme = props.scheme || 'cavos';
  if (!rpId) throw new Error('@cavos/kit plugin requires `rpId`');

  if (props.enableAssociatedDomains !== false) {
    config = withEntitlementsPlist(config, (result) => {
      const domains = new Set(result.modResults['com.apple.developer.associated-domains'] || []);
      domains.add(`webcredentials:${rpId}`);
      for (const domain of props.associatedDomains || []) domains.add(domain);
      result.modResults['com.apple.developer.associated-domains'] = [...domains];
      return result;
    });
  }
  config = withInfoPlist(config, (result) => {
    const types = result.modResults.CFBundleURLTypes || [];
    types.push({ CFBundleURLSchemes: [scheme] });
    result.modResults.CFBundleURLTypes = types;
    return result;
  });
  return withAndroidManifest(config, (result) => {
    const activity = result.modResults.manifest.application?.[0]?.activity?.[0];
    if (!activity) return result;
    activity['intent-filter'] ||= [];
    activity['intent-filter'].push({
      action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
      category: [
        { $: { 'android:name': 'android.intent.category.DEFAULT' } },
        { $: { 'android:name': 'android.intent.category.BROWSABLE' } },
      ],
      data: [{ $: { 'android:scheme': scheme } }],
    });
    activity['intent-filter'].push({
      $: { 'android:autoVerify': 'true' },
      action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
      category: [
        { $: { 'android:name': 'android.intent.category.DEFAULT' } },
        { $: { 'android:name': 'android.intent.category.BROWSABLE' } },
      ],
      data: [{ $: {
        'android:scheme': 'https',
        'android:host': rpId,
        ...(props.androidPathPrefix ? { 'android:pathPrefix': props.androidPathPrefix } : {}),
      } }],
    });
    return result;
  });
};
