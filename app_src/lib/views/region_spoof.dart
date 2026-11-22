import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:material_ui/material_ui.dart';

class RegionSpoofView extends StatefulWidget {
  const RegionSpoofView({super.key});

  @override
  State<RegionSpoofView> createState() => _RegionSpoofViewState();
}

class _RegionSpoofViewState extends State<RegionSpoofView> {
  RegionSpoofStatus? _status;
  bool _loading = true;
  bool _busy = false;
  bool _spoofSim = true;
  bool _spoofLocale = true;
  bool _spoofTimezone = true;
  bool _autoMatchProxy = true;
  bool _autoRestoreOnStop = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final st = await RootHelperApi.getRegionStatus();
      if (!mounted) return;
      setState(() {
        _status = st;
        _spoofSim = st.spoofSim;
        _spoofLocale = st.spoofLocale;
        _spoofTimezone = st.spoofTimezone;
        _autoMatchProxy = st.autoMatchProxy;
        _autoRestoreOnStop = st.autoRestoreOnStop;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _loading = false;
      });
    }
  }

  Future<void> _updateConfig({
    bool? spoofSim,
    bool? spoofLocale,
    bool? spoofTimezone,
    bool? autoMatchProxy,
    bool? autoRestoreOnStop,
  }) async {
    setState(() {
      if (spoofSim != null) _spoofSim = spoofSim;
      if (spoofLocale != null) _spoofLocale = spoofLocale;
      if (spoofTimezone != null) _spoofTimezone = spoofTimezone;
      if (autoMatchProxy != null) _autoMatchProxy = autoMatchProxy;
      if (autoRestoreOnStop != null) _autoRestoreOnStop = autoRestoreOnStop;
    });
    try {
      final st = await RootHelperApi.updateRegionConfig(
        spoofSim: spoofSim,
        spoofLocale: spoofLocale,
        spoofTimezone: spoofTimezone,
        autoMatchProxy: autoMatchProxy,
        autoRestoreOnStop: autoRestoreOnStop,
      );
      if (!mounted) return;
      setState(() => _status = st);
    } catch (e) {
      if (!mounted) return;
      context.showNotifier('保存设置失败: $e', level: MessageLevel.error);
    }
  }

  Future<void> _apply(RegionPresetInfo preset) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final st = await RootHelperApi.applyRegion(
        code: preset.code,
        spoofSim: _spoofSim,
        spoofLocale: _spoofLocale,
        spoofTimezone: _spoofTimezone,
        autoMatchProxy: false,
      );
      if (!mounted) return;
      setState(() {
        _status = st;
        _autoMatchProxy = st.autoMatchProxy;
        _busy = false;
      });
      context.showNotifier(
        '已手动固定伪装: ${preset.name} (${preset.code}) · ${preset.timezone}',
      );
    } catch (e) {
      if (!mounted) return;
      setState(() => _busy = false);
      context.showNotifier('切换失败: $e', level: MessageLevel.error);
    }
  }

  Future<void> _syncNow() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      final st = await RootHelperApi.syncAutoRegion(
        code: '',
        mixedPort: RootHelperApi.configuredMixedPort,
      );
      if (!mounted) return;
      setState(() {
        _status = st;
        _busy = false;
      });
      if (st.enabled) {
        context.showNotifier(
          '已按出口 ${st.detectedExitIp.isEmpty ? st.code : st.detectedExitIp} 同步: ${st.code} · ${st.activeTimezone}',
        );
      } else {
        context.showNotifier('当前代理未开启或出口为中国直连，保持原生状态');
      }
    } catch (e) {
      if (!mounted) return;
      setState(() => _busy = false);
      context.showNotifier('探测同步失败: $e', level: MessageLevel.error);
    }
  }

  Future<void> _restore() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final st = await RootHelperApi.restoreRegion();
      if (!mounted) return;
      setState(() {
        _status = st;
        _busy = false;
      });
      context.showNotifier('已关闭伪装并还原系统真实基线');
    } catch (e) {
      if (!mounted) return;
      setState(() => _busy = false);
      context.showNotifier('还原失败: $e', level: MessageLevel.error);
    }
  }

  @override
  Widget build(BuildContext context) {
    final st = _status;
    return CommonScaffold(
      title: '地区与时区伪装',
      actions: [
        IconButton(
          onPressed: _busy ? null : _refresh,
          icon: const Icon(Icons.refresh),
        ),
      ],
      body: _loading && st == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                if (_error != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Card(
                      color: context.colorScheme.errorContainer,
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Text(
                          '连接后端失败: $_error',
                          style: TextStyle(
                            color: context.colorScheme.onErrorContainer,
                          ),
                        ),
                      ),
                    ),
                  ),
                if (st != null) ...[
                  generateSection(
                    title: '当前系统指纹状态',
                    items: [
                      ListItem(
                        title: Text(
                          st.enabled ? '伪装运行中 (${st.code})' : '未启用伪装（原生状态）',
                        ),
                        subtitle: Text(
                          'SIM: ${st.activeIso.isEmpty ? "-" : st.activeIso} | '
                          '${st.activeAlpha.isEmpty ? "-" : st.activeAlpha} (${st.activeNumeric.isEmpty ? "-" : st.activeNumeric})\n'
                          '语言: ${st.activeLocale.isEmpty ? "-" : st.activeLocale}   '
                          '时区: ${st.activeTimezone.isEmpty ? "-" : st.activeTimezone}'
                          '${st.detectedExitIp.isNotEmpty ? '\n出口 IP: ${st.detectedExitIp}' : ''}',
                        ),
                        trailing: st.enabled
                            ? FilledButton.tonal(
                                onPressed: _busy ? null : _restore,
                                child: const Text('关闭还原'),
                              )
                            : null,
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  generateSection(
                    title: '代理出口联动（自动跟随节点 IP 切换）',
                    items: [
                      ListItem(
                        title: const Text('跟随代理出口自动伪装'),
                        subtitle: const Text('开启代理或切换节点时自动探测出口国家与城市时区并同步伪装'),
                        trailing: Switch(
                          value: _autoMatchProxy,
                          onChanged: (v) => _updateConfig(autoMatchProxy: v),
                        ),
                        onTap: () =>
                            _updateConfig(autoMatchProxy: !_autoMatchProxy),
                      ),
                      ListItem(
                        title: const Text('关闭代理时自动还原原生'),
                        subtitle: const Text('停止 TProxy 后恢复真机 SIM / 语言 / 时区基线'),
                        trailing: Switch(
                          value: _autoRestoreOnStop,
                          onChanged: (v) =>
                              _updateConfig(autoRestoreOnStop: v),
                        ),
                        onTap: () => _updateConfig(
                          autoRestoreOnStop: !_autoRestoreOnStop,
                        ),
                      ),
                      if (_autoMatchProxy)
                        ListItem(
                          title: const Text('立即探测代理出口并同步伪装'),
                          subtitle: const Text('按当前实际出站节点 IP 立即刷新地区与时区'),
                          trailing: const Icon(Icons.my_location),
                          onTap: _busy ? null : _syncNow,
                        ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  generateSection(
                    title: '伪装维度开关',
                    items: [
                      ListItem(
                        title: const Text('伪装 SIM 与运营商 / 区域码'),
                        subtitle: const Text('修改 gsm.* 与 ro.config/miui.region'),
                        trailing: Switch(
                          value: _spoofSim,
                          onChanged: (v) => _updateConfig(spoofSim: v),
                        ),
                        onTap: () => _updateConfig(spoofSim: !_spoofSim),
                      ),
                      ListItem(
                        title: const Text('伪装系统语言区域'),
                        subtitle: const Text('修改 persist.sys.locale 与 ro.product.locale'),
                        trailing: Switch(
                          value: _spoofLocale,
                          onChanged: (v) => _updateConfig(spoofLocale: v),
                        ),
                        onTap: () => _updateConfig(spoofLocale: !_spoofLocale),
                      ),
                      ListItem(
                        title: const Text('伪装系统时区'),
                        subtitle: const Text('关闭自动时区并注入对应国家/城市 Olson 时区'),
                        trailing: Switch(
                          value: _spoofTimezone,
                          onChanged: (v) => _updateConfig(spoofTimezone: v),
                        ),
                        onTap: () =>
                            _updateConfig(spoofTimezone: !_spoofTimezone),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  generateSection(
                    title: '手动固定地区（点击将关闭自动跟随并固定为所选地区 · ${st.presets.length} 个）',
                    items: st.presets.map((preset) {
                      final selected = st.enabled && st.code == preset.code;
                      return ListItem(
                        title: Text('${preset.name} (${preset.code})'),
                        subtitle: Text(
                          '${preset.alpha} · ${preset.numeric} · ${preset.locale} · ${preset.timezone}',
                        ),
                        trailing: selected
                            ? Icon(
                                Icons.check_circle,
                                color: context.colorScheme.primary,
                              )
                            : const Icon(Icons.chevron_right),
                        onTap: _busy ? null : () => _apply(preset),
                      );
                    }),
                  ),
                ],
              ],
            ),
    );
  }
}
