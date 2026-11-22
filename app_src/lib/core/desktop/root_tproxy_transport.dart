import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';

import 'lifecycle.dart';
import 'model.dart';
import 'transport.dart';

const int defaultRootTProxyPort = 7893;
const int defaultRootTProxyDnsPort = 1053;
const int rootTProxyRoutingMark = 150994944; // 0x09000000 bypass mark

final class RootHelperStatus {
  final bool coreRunning;
  final bool tproxyActive;
  final int pid;
  final String coreAddr;
  final String coreToken;
  final int tproxyPort;
  final int startedAtMillis;

  const RootHelperStatus({
    required this.coreRunning,
    required this.tproxyActive,
    required this.pid,
    required this.coreAddr,
    required this.coreToken,
    required this.tproxyPort,
    required this.startedAtMillis,
  });

  factory RootHelperStatus.fromJson(Map<String, dynamic> json) {
    return RootHelperStatus(
      coreRunning: json['coreRunning'] == true,
      tproxyActive: json['tproxyActive'] == true,
      pid: (json['pid'] as num?)?.toInt() ?? 0,
      coreAddr: json['coreAddr'] as String? ?? '',
      coreToken: json['coreToken'] as String? ?? '',
      tproxyPort: (json['tproxyPort'] as num?)?.toInt() ?? defaultRootTProxyPort,
      startedAtMillis: (json['startedAtMillis'] as num?)?.toInt() ?? 0,
    );
  }
}

final class RootHelperApi {
  static bool configuredIPv6 = false;
  static int configuredMixedPort = defaultMixedPort;

  static Uri _uri(String path) => Uri.parse('http://$localhost:$helperPort$path');

  static HttpClient _newClient() {
    final client = HttpClient();
    client.findProxy = (_) => 'DIRECT';
    client.connectionTimeout = const Duration(seconds: 3);
    return client;
  }

  static Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, Object?>? body,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final client = _newClient();
    try {
      final req = await client.openUrl(method, _uri(path)).timeout(timeout);
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      if (body != null) {
        req.add(utf8.encode(jsonEncode(body)));
      }
      final resp = await req.close().timeout(timeout);
      final raw = await utf8.decoder.bind(resp).join().timeout(timeout);
      final decoded = raw.isEmpty ? <String, dynamic>{} : jsonDecode(raw);
      final map = decoded is Map
          ? Map<String, dynamic>.from(decoded)
          : <String, dynamic>{};
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw StateError(
          'Helper $path HTTP ${resp.statusCode}: ${map['message'] ?? raw}',
        );
      }
      return map;
    } finally {
      client.close(force: true);
    }
  }

  static Future<({int pid, String coreAddr, String coreToken})> ensureCore() async {
    final map = await _request('POST', '/core/ensure');
    final pid = (map['pid'] as num?)?.toInt() ?? 0;
    final coreAddr = map['coreAddr'] as String? ?? '';
    final coreToken = map['coreToken'] as String? ?? '';
    if (pid <= 0 || coreAddr.isEmpty || coreToken.isEmpty) {
      throw StateError('Invalid /core/ensure response from flclash-helper');
    }
    return (pid: pid, coreAddr: coreAddr, coreToken: coreToken);
  }

  static Future<RootHelperStatus> getStatus() async {
    final map = await _request('GET', '/status');
    return RootHelperStatus.fromJson(map);
  }

  static Future<DateTime?> getTProxyStartTime() async {
    try {
      final status = await getStatus();
      if (!status.tproxyActive || status.startedAtMillis <= 0) {
        return null;
      }
      return DateTime.fromMillisecondsSinceEpoch(status.startedAtMillis);
    } catch (e) {
      commonPrint.log('getTProxyStartTime failed: $e', logLevel: LogLevel.warning);
      return null;
    }
  }

  static Future<bool> startTProxy({
    int tproxyPort = defaultRootTProxyPort,
    int dnsPort = defaultRootTProxyDnsPort,
    int? mixedPort,
    bool dnsHijack = true,
    bool? enableIPv6,
  }) async {
    await _request(
      'POST',
      '/tproxy/start',
      body: {
        'tproxyPort': tproxyPort,
        'dnsPort': dnsPort,
        'mixedPort': mixedPort ?? configuredMixedPort,
        'dnsHijack': dnsHijack,
        'enableIPv6': enableIPv6 ?? configuredIPv6,
      },
    );
    return true;
  }

  static Future<bool> stopTProxy() async {
    await _request('POST', '/tproxy/stop');
    return true;
  }

  static Future<RegionSpoofStatus> getRegionStatus() async {
    final map = await _request('GET', '/region/status');
    return RegionSpoofStatus.fromJson(map);
  }

  static Future<RegionSpoofStatus> updateRegionConfig({
    bool? spoofSim,
    bool? spoofLocale,
    bool? spoofTimezone,
    bool? autoMatchProxy,
    bool? autoRestoreOnStop,
  }) async {
    final map = await _request(
      'POST',
      '/region/config',
      body: {
        'spoofSim': ?spoofSim,
        'spoofLocale': ?spoofLocale,
        'spoofTimezone': ?spoofTimezone,
        'autoMatchProxy': ?autoMatchProxy,
        'autoRestoreOnStop': ?autoRestoreOnStop,
      },
      timeout: const Duration(seconds: 20),
    );
    return RegionSpoofStatus.fromJson(map);
  }

  static Future<RegionSpoofStatus> applyRegion({
    required String code,
    bool spoofSim = true,
    bool spoofLocale = true,
    bool spoofTimezone = true,
    bool? autoMatchProxy,
  }) async {
    final map = await _request(
      'POST',
      '/region/apply',
      body: {
        'code': code,
        'spoofSim': spoofSim,
        'spoofLocale': spoofLocale,
        'spoofTimezone': spoofTimezone,
        'autoMatchProxy': ?autoMatchProxy,
      },
      timeout: const Duration(seconds: 20),
    );
    return RegionSpoofStatus.fromJson(map);
  }

  static Future<RegionSpoofStatus> syncAutoRegion({
    required String code,
    String? ip,
    int? mixedPort,
  }) async {
    final map = await _request(
      'POST',
      '/region/sync',
      body: {
        'code': code,
        if (ip != null && ip.isNotEmpty) 'ip': ip,
        'mixedPort': mixedPort ?? configuredMixedPort,
      },
      timeout: const Duration(seconds: 20),
    );
    return RegionSpoofStatus.fromJson(map);
  }

  static Future<RegionSpoofStatus> restoreRegion() async {
    final map = await _request(
      'POST',
      '/region/restore',
      timeout: const Duration(seconds: 20),
    );
    return RegionSpoofStatus.fromJson(map);
  }
}

final class RegionPresetInfo {
  final String code;
  final String name;
  final String alpha;
  final String numeric;
  final String locale;
  final String timezone;

  const RegionPresetInfo({
    required this.code,
    required this.name,
    required this.alpha,
    required this.numeric,
    required this.locale,
    required this.timezone,
  });

  factory RegionPresetInfo.fromJson(Map<String, dynamic> json) {
    return RegionPresetInfo(
      code: json['code'] as String? ?? '',
      name: json['name'] as String? ?? '',
      alpha: json['alpha'] as String? ?? '',
      numeric: json['numeric'] as String? ?? '',
      locale: json['locale'] as String? ?? '',
      timezone: json['timezone'] as String? ?? '',
    );
  }
}

final class RegionSpoofStatus {
  final bool enabled;
  final String code;
  final bool spoofSim;
  final bool spoofLocale;
  final bool spoofTimezone;
  final bool autoMatchProxy;
  final bool autoRestoreOnStop;
  final String detectedExitIp;
  final String activeIso;
  final String activeAlpha;
  final String activeNumeric;
  final String activeLocale;
  final String activeTimezone;
  final List<RegionPresetInfo> presets;

  const RegionSpoofStatus({
    required this.enabled,
    required this.code,
    required this.spoofSim,
    required this.spoofLocale,
    required this.spoofTimezone,
    required this.autoMatchProxy,
    required this.autoRestoreOnStop,
    required this.detectedExitIp,
    required this.activeIso,
    required this.activeAlpha,
    required this.activeNumeric,
    required this.activeLocale,
    required this.activeTimezone,
    required this.presets,
  });

  factory RegionSpoofStatus.fromJson(Map<String, dynamic> json) {
    final rawPresets = json['presets'] as List? ?? const [];
    return RegionSpoofStatus(
      enabled: json['enabled'] == true,
      code: json['code'] as String? ?? 'US',
      spoofSim: json['spoofSim'] != false,
      spoofLocale: json['spoofLocale'] != false,
      spoofTimezone: json['spoofTimezone'] != false,
      autoMatchProxy: json['autoMatchProxy'] != false,
      autoRestoreOnStop: json['autoRestoreOnStop'] != false,
      detectedExitIp: json['detectedExitIp'] as String? ?? '',
      activeIso: json['activeIso'] as String? ?? '',
      activeAlpha: json['activeAlpha'] as String? ?? '',
      activeNumeric: json['activeNumeric'] as String? ?? '',
      activeLocale: json['activeLocale'] as String? ?? '',
      activeTimezone: json['activeTimezone'] as String? ?? '',
      presets: rawPresets
          .whereType<Map>()
          .map((e) => RegionPresetInfo.fromJson(e.cast<String, dynamic>()))
          .toList(),
    );
  }
}

final class TcpClientCoreTransport implements DesktopCoreTransport {
  final StreamController<DesktopTransportEvent> _eventController =
      StreamController<DesktopTransportEvent>.broadcast();
  final StreamController<Uint8List> _frameController =
      StreamController<Uint8List>.broadcast();

  Socket? _socket;
  StreamSubscription<Uint8List>? _socketSub;
  Future<void>? _openOperation;
  Future<void>? _closeOperation;
  DesktopTransportState _state = DesktopTransportState.idle;
  TransportConnected? _connection;
  TransportFailed? _failure;
  String _address = '';
  int _generation = 0;

  final BytesBuilder _rxBuffer = BytesBuilder(copy: false);
  Completer<Map<String, dynamic>>? _authCompleter;

  @override
  String get address => _address;

  @override
  DesktopTransportState get state => _state;

  @override
  Stream<DesktopTransportEvent> get events => _eventController.stream;

  @override
  Stream<Uint8List> get frames => _frameController.stream;

  @override
  Future<void> open() {
    if (_state == DesktopTransportState.closed) {
      return Future.error(StateError('TCP core transport is closed'));
    }
    final failure = _failure;
    if (failure != null) {
      return Future.error(failure.error, failure.stackTrace);
    }
    return _openOperation ??= _open();
  }

  Future<void> _open() async {
    _state = DesktopTransportState.starting;
    try {
      final info = await RootHelperApi.ensureCore();
      _address = info.coreAddr;
      final sep = info.coreAddr.lastIndexOf(':');
      if (sep <= 0) {
        throw StateError('Invalid coreAddr: ${info.coreAddr}');
      }
      final host = info.coreAddr.substring(0, sep);
      final port = int.parse(info.coreAddr.substring(sep + 1));

      final socket = await Socket.connect(
        host,
        port,
        timeout: const Duration(seconds: 5),
      );
      if (_state == DesktopTransportState.closed) {
        socket.destroy();
        throw StateError('TCP core transport closed during connect');
      }
      socket.setOption(SocketOption.tcpNoDelay, true);
      _socket = socket;
      _state = DesktopTransportState.ready;
      _eventController.add(const TransportReady());

      final authCompleter = Completer<Map<String, dynamic>>();
      _authCompleter = authCompleter;

      _socketSub = socket.listen(
        _onData,
        onError: _onSocketError,
        onDone: _onSocketDone,
        cancelOnError: true,
      );

      final authFrame = utf8.encode(
        jsonEncode({
          'id': '0',
          'method': 'auth',
          'arguments': {'token': info.coreToken},
        }),
      );
      _writeFrame(socket, authFrame);

      final authResp = await authCompleter.future.timeout(
        const Duration(seconds: 5),
      );
      if (authResp['error'] != null || authResp['result'] != true) {
        throw StateError('Daemon core auth failed: $authResp');
      }

      final connection = TransportConnected(
        pid: info.pid,
        generation: ++_generation,
      );
      _connection = connection;
      _state = DesktopTransportState.connected;
      _eventController.add(connection);
    } catch (error, stackTrace) {
      _fail(error, stackTrace);
      rethrow;
    }
  }

  void _onData(Uint8List chunk) {
    _rxBuffer.add(chunk);
    final bytes = _rxBuffer.takeBytes();
    var offset = 0;

    while (bytes.length - offset >= 4) {
      final length = ByteData.sublistView(
        bytes,
        offset,
        offset + 4,
      ).getUint32(0, Endian.little);
      if (length > 64 * 1024 * 1024) {
        _fail(
          StateError('IPC frame exceeds 64MB: $length'),
          StackTrace.current,
        );
        return;
      }
      if (bytes.length - offset - 4 < length) {
        break;
      }
      final payload = Uint8List.fromList(
        bytes.sublist(offset + 4, offset + 4 + length),
      );
      offset += 4 + length;

      final authCompleter = _authCompleter;
      if (authCompleter != null && !authCompleter.isCompleted) {
        _authCompleter = null;
        try {
          final decoded = jsonDecode(utf8.decode(payload));
          authCompleter.complete(
            decoded is Map
                ? Map<String, dynamic>.from(decoded)
                : <String, dynamic>{},
          );
        } catch (e, st) {
          authCompleter.completeError(e, st);
        }
        continue;
      }

      if (!_frameController.isClosed) {
        _frameController.add(payload);
      }
    }

    if (offset < bytes.length) {
      _rxBuffer.add(Uint8List.sublistView(bytes, offset));
    }
  }

  void _onSocketError(Object error, StackTrace stackTrace) {
    final authCompleter = _authCompleter;
    if (authCompleter != null && !authCompleter.isCompleted) {
      authCompleter.completeError(error, stackTrace);
    }
    _fail(error, stackTrace);
  }

  void _onSocketDone() {
    final authCompleter = _authCompleter;
    if (authCompleter != null && !authCompleter.isCompleted) {
      authCompleter.completeError(StateError('Daemon closed during auth'));
    }
    final connection = _connection;
    if (connection == null) {
      _fail(StateError('Daemon socket closed'), StackTrace.current);
      return;
    }
    _connection = null;
    if (_state != DesktopTransportState.closed) {
      _state = DesktopTransportState.ready;
      _eventController.add(TransportDisconnected(connection.generation));
    }
  }

  void _fail(Object error, StackTrace stackTrace) {
    if (_state == DesktopTransportState.failed ||
        _state == DesktopTransportState.closed) {
      return;
    }
    _connection = null;
    final failure = TransportFailed(error, stackTrace);
    _failure = failure;
    _state = DesktopTransportState.failed;
    if (!_eventController.isClosed) {
      _eventController.add(failure);
    }
  }

  void _writeFrame(Socket socket, List<int> frame) {
    final header = ByteData(4)..setUint32(0, frame.length, Endian.little);
    socket.add(header.buffer.asUint8List());
    socket.add(frame);
  }

  @override
  Future<TransportConnected> waitUntilConnected(Duration timeout) {
    final connection = _connection;
    if (connection != null) {
      return Future.value(connection);
    }
    final failure = _failure;
    if (failure != null) {
      return Future.error(failure.error, failure.stackTrace);
    }
    return events
        .firstWhere(
          (event) => event is TransportConnected || event is TransportFailed,
        )
        .then<TransportConnected>((event) {
          if (event case TransportConnected()) {
            return event;
          }
          final f = event as TransportFailed;
          Error.throwWithStackTrace(f.error, f.stackTrace);
        })
        .timeout(timeout);
  }

  @override
  void send(List<int> frame) {
    final socket = _socket;
    if (socket == null || _state != DesktopTransportState.connected) {
      throw StateError('TCP core transport is not connected');
    }
    _writeFrame(socket, frame);
  }

  @override
  Future<void> close() {
    return _closeOperation ??= _close();
  }

  Future<void> _close() async {
    _state = DesktopTransportState.closed;
    _connection = null;
    await _socketSub?.cancel();
    _socket?.destroy();
    _socket = null;
    await _eventController.close();
    await _frameController.close();
  }
}

final class _DetachedProcessLease implements CoreProcessLease {
  @override
  final String sessionId;

  @override
  final int pid;

  const _DetachedProcessLease({required this.sessionId, required this.pid});

  @override
  CoreProcessOwner get owner => CoreProcessOwner.helper;

  // Never kill the persistent Root Core when the frontend disconnects.
  @override
  Future<CoreProcessStopResult> stop(Duration timeout) async {
    return const CoreProcessStopResult(stopped: false, exitConfirmed: true);
  }
}

final class RootTProxyLifecycle implements DesktopCoreLifecycleController {
  final DesktopCoreTransportBinding transport = DesktopCoreTransportBinding(
    TcpClientCoreTransport(),
  );
  final StreamController<DesktopCoreState> _states =
      StreamController<DesktopCoreState>.broadcast();
  final StreamController<DesktopCoreFailure> _crashes =
      StreamController<DesktopCoreFailure>.broadcast();

  DesktopCoreState _state = const DesktopCoreIdle();
  int _revision = 0;
  Future<CoreLifecycleResult>? _closing;
  late final StreamSubscription<DesktopTransportEvent> _sub;

  RootTProxyLifecycle() {
    _sub = transport.events.listen((event) {
      switch (event) {
        case TransportDisconnected(:final generation, :final error):
          final failure = DesktopCoreFailure(
            code: 'unexpected_disconnect',
            phase: DesktopCorePhase.running,
            revision: _revision,
            connectionGeneration: generation,
            cause: error,
          );
          _state = DesktopCoreFailed(failure);
          _states.add(_state);
          _crashes.add(failure);
        case TransportFailed(:final error, :final stackTrace):
          final failure = DesktopCoreFailure(
            code: 'transport_failed',
            phase: DesktopCorePhase.running,
            revision: _revision,
            cause: error,
            stackTrace: stackTrace,
          );
          _state = DesktopCoreFailed(failure);
          _states.add(_state);
          _crashes.add(failure);
        case TransportReady() || TransportConnected():
          break;
      }
    });
  }

  @override
  DesktopCoreState get state => _state;

  @override
  Stream<DesktopCoreState> get states => _states.stream;

  @override
  Stream<DesktopCoreFailure> get crashEvents => _crashes.stream;

  @override
  Future<CoreLifecycleResult> start() async {
    final rev = ++_revision;
    final sessionId = createCoreSessionId();
    _state = DesktopCoreStarting(revision: rev, sessionId: sessionId);
    _states.add(_state);
    await transport.open();
    final connected = await transport.waitUntilConnected(
      const Duration(seconds: 10),
    );
    final session = DesktopCoreSession(
      sessionId: sessionId,
      lease: _DetachedProcessLease(
        sessionId: sessionId,
        pid: connected.pid ?? 1,
      ),
      connectionGeneration: connected.generation,
    );
    _state = DesktopCoreRunning(session);
    _states.add(_state);
    return CoreLifecycleResult(
      revision: rev,
      outcome: CoreLifecycleOutcome.applied,
      session: session,
    );
  }

  @override
  Future<CoreLifecycleResult> restart() async {
    await transport.replace(TcpClientCoreTransport());
    return start();
  }

  @override
  Future<CoreLifecycleResult> stop() async {
    final rev = ++_revision;
    await transport.replace(TcpClientCoreTransport());
    _state = const DesktopCoreIdle();
    _states.add(_state);
    return CoreLifecycleResult(
      revision: rev,
      outcome: CoreLifecycleOutcome.applied,
    );
  }

  @override
  Future<CoreLifecycleResult> close() {
    return _closing ??= _close();
  }

  Future<CoreLifecycleResult> _close() async {
    final rev = ++_revision;
    await _sub.cancel();
    await transport.close();
    _state = DesktopCoreClosed(rev);
    _states.add(_state);
    await _states.close();
    await _crashes.close();
    return CoreLifecycleResult(
      revision: rev,
      outcome: CoreLifecycleOutcome.applied,
    );
  }

  @override
  Future<DesktopCoreSession> waitUntilRunning(Duration timeout) async {
    final cur = _state;
    if (cur is DesktopCoreRunning) {
      return cur.session;
    }
    final result = await start().timeout(timeout);
    return result.session!;
  }
}
